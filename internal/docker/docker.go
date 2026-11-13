// Package docker is the small part of the Docker Engine API the functions
// service uses, spoken with net/http over the daemon's socket: inspecting
// and pulling images, and creating, attaching to, starting, pausing,
// waiting on, listing and removing containers, and finding the address the
// containers reach the host at.
//
// Every call but the ping names the API version, APIVersion, the oldest
// with every field used here; Ping refuses a daemon older than that.
// Redirects are never followed: the daemon answers a path it cleans with a
// 301, and following it would run another call than the one asked for.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// APIVersion is the Engine API version the client speaks: 1.41, of Docker
// 20.10.
const APIVersion = "1.41"

// ErrNotFound is returned for an image or a container the daemon does not
// have.
var ErrNotFound = errors.New("docker: not found")

// Client talks to one Docker daemon.
type Client struct {
	http *http.Client
	base string
}

// New returns a client for host, a unix:// socket path or a tcp://
// host:port, the forms DOCKER_HOST takes.
func New(host string) (*Client, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("docker: host %q: %w", host, err)
	}
	transport := &http.Transport{DisableCompression: true}
	var network, addr string
	switch u.Scheme {
	case "unix":
		network, addr = "unix", u.Path
	case "tcp":
		network, addr = "tcp", u.Host
	default:
		return nil, fmt.Errorf("docker: host %q is not a unix:// or tcp:// address", host)
	}
	if addr == "" {
		return nil, fmt.Errorf("docker: host %q names no address", host)
	}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	// The host in the URL is a placeholder: every connection goes where
	// DialContext says.
	return &Client{
		http: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		base: "http://docker",
	}, nil
}

// escapePath escapes each /-separated segment of p for a URL path.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// apiError is the body the daemon answers a failed request with.
type apiError struct {
	Message string `json:"message"`
}

// do sends a request for the versioned path with an optional JSON body and
// returns the response, or an error for any status but 2xx: ErrNotFound for
// 404.
func (c *Client) do(
	ctx context.Context,
	method, path string,
	query url.Values,
	body any,
) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("docker: encode %s %s: %w", method, path, err)
		}
		rd = bytes.NewReader(b)
	}
	u := c.base + "/v" + APIVersion + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, fmt.Errorf("docker: %s %s: %w", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker: %s %s: %w", method, path, err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	return nil, responseError(method, path, resp)
}

func responseError(method, path string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var e apiError
	msg := strings.TrimSpace(string(b))
	if json.Unmarshal(b, &e) == nil && e.Message != "" {
		msg = e.Message
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, msg)
	}
	return fmt.Errorf("docker: %s %s: %d %s", method, path, resp.StatusCode, msg)
}

// doJSON sends a request and decodes its JSON answer into out, when out is
// not nil.
func (c *Client) doJSON(
	ctx context.Context,
	method, path string,
	query url.Values,
	body, out any,
) error {
	resp, err := c.do(ctx, method, path, query, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err = json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("docker: decode %s %s: %w", method, path, err)
	}
	return nil
}

// Ping checks the daemon answers and speaks APIVersion or later.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/_ping", http.NoBody)
	if err != nil {
		return fmt.Errorf("docker: ping: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker: ping: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return responseError(http.MethodGet, "/_ping", resp)
	}
	version := resp.Header.Get("Api-Version")
	if !atLeast(version, APIVersion) {
		return fmt.Errorf("docker: the daemon speaks Engine API %q; functions needs %s "+
			"or later (Docker 20.10)", version, APIVersion)
	}
	return nil
}

// atLeast reports whether the version major.minor is want or later.
func atLeast(version, want string) bool {
	parse := func(v string) (int, int, bool) {
		maj, minor, ok := strings.Cut(v, ".")
		a, aErr := strconv.Atoi(maj)
		b, bErr := strconv.Atoi(minor)
		return a, b, ok && aErr == nil && bErr == nil
	}
	va, vb, ok := parse(version)
	wa, wb, _ := parse(want)
	return ok && (va > wa || (va == wa && vb >= wb))
}

// Image is what the functions service reads of an image.
type Image struct {
	Config       ImageConfig `json:"Config"`
	ID           string      `json:"Id"`
	Architecture string      `json:"Architecture"`
	Os           string      `json:"Os"`
	RepoDigests  []string    `json:"RepoDigests"`
}

// ImageConfig is an image's default entry point and command.
type ImageConfig struct {
	Entrypoint []string `json:"Entrypoint"`
	Cmd        []string `json:"Cmd"`
}

// InspectImage returns the image ref names, or ErrNotFound. ref must be a
// reference ParseReference accepted.
func (c *Client) InspectImage(ctx context.Context, ref string) (*Image, error) {
	var img Image
	err := c.doJSON(ctx, http.MethodGet, "/images/"+escapePath(ref)+"/json", nil, nil, &img)
	if err != nil {
		return nil, err
	}
	return &img, nil
}

// pullMessage is one line of a pull's progress stream; a failed pull ends
// with one that carries an error.
type pullMessage struct {
	Error string `json:"error"`
}

// PullImage asks the daemon to pull ref, and waits for the pull to finish.
// It always names the tag or digest: without one the daemon would pull
// every tag of the repository.
func (c *Client) PullImage(ctx context.Context, ref *Reference) error {
	resp, err := c.do(ctx, http.MethodPost, "/images/create",
		url.Values{"fromImage": {ref.Name}, "tag": {ref.TagOrDigest}}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	dec := json.NewDecoder(resp.Body)
	for {
		var m pullMessage
		if dErr := dec.Decode(&m); errors.Is(dErr, io.EOF) {
			return nil
		} else if dErr != nil {
			return fmt.Errorf("docker: pull %s: %w", ref, dErr)
		}
		if m.Error != "" {
			return fmt.Errorf("docker: pull %s: %s", ref, m.Error)
		}
	}
}

// ContainerSpec is what a container is created with. MemoryBytes is both
// its memory and its memory-and-swap limit, so it gets no swap; PidsLimit
// bounds its processes; LogMaxSize bounds what Docker keeps of its output.
type ContainerSpec struct {
	Labels      map[string]string
	Name        string
	Image       string
	WorkingDir  string
	LogMaxSize  string
	Env         []string
	Entrypoint  []string
	Cmd         []string
	ExtraHosts  []string
	MemoryBytes int64
	PidsLimit   int64
}

type createBody struct {
	Labels     map[string]string `json:"Labels"`
	Image      string            `json:"Image"`
	WorkingDir string            `json:"WorkingDir,omitempty"`
	Env        []string          `json:"Env"`
	Entrypoint []string          `json:"Entrypoint,omitempty"`
	Cmd        []string          `json:"Cmd,omitempty"`
	HostConfig hostConfig        `json:"HostConfig"`
	// The stdio a later attach reads: without them the daemon drops the
	// output an attach made before start would see.
	AttachStdout bool `json:"AttachStdout"`
	AttachStderr bool `json:"AttachStderr"`
}

type hostConfig struct {
	LogConfig  logConfig `json:"LogConfig"`
	ExtraHosts []string  `json:"ExtraHosts,omitempty"`
	Memory     int64     `json:"Memory,omitempty"`
	MemorySwap int64     `json:"MemorySwap,omitempty"`
	PidsLimit  int64     `json:"PidsLimit,omitempty"`
}

type logConfig struct {
	Config map[string]string `json:"Config"`
	Type   string            `json:"Type"`
}

// CreateContainer creates a container and returns its ID. It never pulls:
// an image the daemon does not have fails with ErrNotFound. Its output is
// kept by Docker's local log driver, bounded to LogMaxSize in one file,
// whatever the daemon's default driver is.
func (c *Client) CreateContainer(ctx context.Context, spec *ContainerSpec) (string, error) {
	body := createBody{
		Labels:     spec.Labels,
		Image:      spec.Image,
		WorkingDir: spec.WorkingDir,
		Env:        spec.Env,
		Entrypoint: spec.Entrypoint,
		Cmd:        spec.Cmd,
		HostConfig: hostConfig{
			ExtraHosts: spec.ExtraHosts,
			Memory:     spec.MemoryBytes,
			MemorySwap: spec.MemoryBytes,
			PidsLimit:  spec.PidsLimit,
			LogConfig: logConfig{
				Type: "local",
				Config: map[string]string{
					"max-size": spec.LogMaxSize, "max-file": "1", "compress": "false",
				},
			},
		},
		AttachStdout: true,
		AttachStderr: true,
	}
	var out struct {
		ID string `json:"Id"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/containers/create",
		url.Values{"name": {spec.Name}}, body, &out)
	if err != nil {
		return "", err
	}
	return out.ID, nil
}

// ContainerLimits is what a container was created with, as Docker reports.
type ContainerLimits struct {
	LogConfig  logConfig `json:"LogConfig"`
	Memory     int64     `json:"Memory"`
	MemorySwap int64     `json:"MemorySwap"`
	PidsLimit  int64     `json:"PidsLimit"`
}

// LogDriver returns the log driver and its options.
func (l *ContainerLimits) LogDriver() (string, map[string]string) {
	return l.LogConfig.Type, l.LogConfig.Config
}

// ContainerInfo is what InspectContainer reports of a container.
type ContainerInfo struct {
	Name   string
	Limits ContainerLimits
	Paused bool
}

// InspectContainer returns the container's name, its limits, and whether
// it is paused.
func (c *Client) InspectContainer(ctx context.Context, id string) (*ContainerInfo, error) {
	var out struct {
		Name       string          `json:"Name"`
		HostConfig ContainerLimits `json:"HostConfig"`
		State      struct {
			Paused bool `json:"Paused"`
		} `json:"State"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/containers/"+escapePath(id)+"/json", nil, nil, &out)
	if err != nil {
		return nil, err
	}
	return &ContainerInfo{Name: out.Name, Limits: out.HostConfig, Paused: out.State.Paused}, nil
}

// Attach returns the container's stdout and stderr as the daemon streams
// them: multiplexed frames, which Demux splits. It is called before Start,
// so no output is missed, and ends when the container exits.
func (c *Client) Attach(ctx context.Context, id string) (io.ReadCloser, error) {
	path := "/containers/" + escapePath(id) + "/attach"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/v"+APIVersion+path+"?stream=1&stdout=1&stderr=1", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("docker: attach %s: %w", id, err)
	}
	// The daemon hijacks the connection; asking to upgrade it makes the
	// answer a 101, whose body net/http hands over as the raw connection.
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker: attach %s: %w", id, err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		return nil, responseError(http.MethodPost, path, resp)
	}
	return resp.Body, nil
}

// StartContainer starts a created container.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+escapePath(id)+"/start", nil, nil, nil)
}

// PauseContainer freezes every process of the container, through the
// cgroup freezer.
func (c *Client) PauseContainer(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+escapePath(id)+"/pause", nil, nil, nil)
}

// UnpauseContainer thaws a paused container.
func (c *Client) UnpauseContainer(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+escapePath(id)+"/unpause", nil, nil, nil)
}

// WaitContainer waits for the container to stop and returns its exit code.
func (c *Client) WaitContainer(ctx context.Context, id string) (int, error) {
	var out struct {
		Error *struct {
			Message string `json:"Message"`
		} `json:"Error"`
		StatusCode int `json:"StatusCode"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/containers/"+escapePath(id)+"/wait", nil, nil, &out)
	if err != nil {
		return 0, err
	}
	if out.Error != nil && out.Error.Message != "" {
		return out.StatusCode, fmt.Errorf("docker: wait %s: %s", id, out.Error.Message)
	}
	return out.StatusCode, nil
}

// RemoveContainer kills the container, paused or not, and removes it. A
// container already gone is not an error.
func (c *Client) RemoveContainer(ctx context.Context, id string) error {
	err := c.doJSON(ctx, http.MethodDelete, "/containers/"+escapePath(id),
		url.Values{"force": {"1"}, "v": {"1"}}, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// ListContainers returns the IDs of every container, running or not, that
// carries the label key=value.
func (c *Client) ListContainers(ctx context.Context, key, value string) ([]string, error) {
	filters, err := json.Marshal(map[string][]string{"label": {key + "=" + value}})
	if err != nil {
		return nil, fmt.Errorf("docker: encode filters: %w", err)
	}
	var out []struct {
		ID string `json:"Id"`
	}
	err = c.doJSON(ctx, http.MethodGet, "/containers/json",
		url.Values{"all": {"1"}, "filters": {string(filters)}}, nil, &out)
	if err != nil {
		return nil, err
	}
	idList := make([]string, 0, len(out))
	for _, c := range out {
		idList = append(idList, c.ID)
	}
	return idList, nil
}

// HostAddress returns the address on the Docker host that the containers
// reach it at: 127.0.0.1 for Docker Desktop, which forwards
// host.docker.internal to the host's loopback, and otherwise the gateway of
// the default bridge network, which host-gateway names.
func (c *Client) HostAddress(ctx context.Context) (string, error) {
	var info struct {
		OperatingSystem string `json:"OperatingSystem"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/info", nil, nil, &info); err != nil {
		return "", err
	}
	if strings.Contains(info.OperatingSystem, "Docker Desktop") {
		return "127.0.0.1", nil
	}
	var bridge struct {
		IPAM struct {
			Config []struct {
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/networks/bridge", nil, nil, &bridge); err != nil {
		return "", err
	}
	for _, cfg := range bridge.IPAM.Config {
		if ip := net.ParseIP(cfg.Gateway); ip != nil && ip.To4() != nil {
			return cfg.Gateway, nil
		}
	}
	return "", errors.New("docker: the bridge network has no IPv4 gateway")
}

// Close drops the client's idle connections.
func (c *Client) Close() {
	c.http.CloseIdleConnections()
}
