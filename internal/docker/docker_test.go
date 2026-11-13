package docker

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeEngine records the requests it gets and answers with handle.
type fakeEngine struct {
	handle   func(w http.ResponseWriter, r *http.Request)
	requests []*http.Request
	mu       sync.Mutex
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r)
	f.mu.Unlock()
	f.handle(w, r)
}

func (f *fakeEngine) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.requests))
	for _, r := range f.requests {
		out = append(out, r.URL.EscapedPath())
	}
	return out
}

func newFake(t *testing.T, handle func(http.ResponseWriter, *http.Request)) (*Client, *fakeEngine) {
	t.Helper()
	f := &fakeEngine{handle: handle}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestARedirectIsNotFollowed(t *testing.T) {
	c, f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1.41/containers/abc/json", http.StatusMovedPermanently)
	})
	_, err := c.InspectImage(t.Context(), "x")
	if err == nil || !strings.Contains(err.Error(), "301") {
		t.Fatalf("inspect = %v, want the 301 as an error", err)
	}
	if got := f.paths(); len(got) != 1 || got[0] != "/v1.41/images/x/json" {
		t.Fatalf("requests = %v, want only the inspect", got)
	}
}

func TestAReferenceIsEscapedSegmentBySegment(t *testing.T) {
	c, f := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Id":"sha256:1"}`))
	})
	for _, ref := range []string{"localhost:5000/team/app:1", "a?b#c/d e"} {
		if _, err := c.InspectImage(t.Context(), ref); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"/v1.41/images/localhost:5000/team/app:1/json",
		"/v1.41/images/a%3Fb%23c/d%20e/json",
	}
	got := f.paths()
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestErrorsCarryTheDaemonsMessage(t *testing.T) {
	status := http.StatusNotFound
	c, _ := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"no such image: x"}`))
	})
	_, err := c.InspectImage(t.Context(), "x")
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "no such image: x") {
		t.Fatalf("404 = %v", err)
	}
	status = http.StatusInternalServerError
	_, err = c.InspectImage(t.Context(), "x")
	if errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "500 no such image: x") {
		t.Fatalf("500 = %v", err)
	}
	// A container already gone is not a failed removal.
	status = http.StatusNotFound
	if err = c.RemoveContainer(t.Context(), "abc"); err != nil {
		t.Fatalf("remove a missing container = %v", err)
	}
}

func TestPingRefusesAnOldDaemon(t *testing.T) {
	version := "1.40"
	c, _ := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Api-Version", version)
		_, _ = w.Write([]byte("OK"))
	})
	if err := c.Ping(t.Context()); err == nil || !strings.Contains(err.Error(), "1.41 or later") {
		t.Fatalf("ping 1.40 = %v", err)
	}
	for _, version = range []string{"1.41", "1.56", "2.0"} {
		if err := c.Ping(t.Context()); err != nil {
			t.Fatalf("ping %s = %v", version, err)
		}
	}
}

func TestAPullNamesTheTag(t *testing.T) {
	c, f := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"done"}`))
	})
	for _, s := range []string{"app", "team/app:v2", "app@sha256:" + strings.Repeat("a", 64)} {
		ref, err := ParseReference(s)
		if err != nil {
			t.Fatal(err)
		}
		if err = c.PullImage(t.Context(), ref); err != nil {
			t.Fatal(err)
		}
	}
	want := []struct{ image, tag string }{
		{"docker.io/library/app", "latest"},
		{"docker.io/team/app", "v2"},
		{"docker.io/library/app", "sha256:" + strings.Repeat("a", 64)},
	}
	for i, w := range want {
		q := f.requests[i].URL.Query()
		if f.requests[i].URL.Path != "/v1.41/images/create" ||
			q.Get("fromImage") != w.image || q.Get("tag") != w.tag {
			t.Errorf("pull %d = %s?%s, want %s:%s", i, f.requests[i].URL.Path,
				f.requests[i].URL.RawQuery, w.image, w.tag)
		}
	}
}

func TestAFailedPullIsAnError(t *testing.T) {
	c, _ := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"pulling"}` + "\n" + `{"error":"denied"}`))
	})
	ref, _ := ParseReference("app")
	if err := c.PullImage(
		t.Context(),
		ref,
	); err == nil ||
		!strings.Contains(err.Error(), "denied") {
		t.Fatalf("pull = %v, want denied", err)
	}
}

func TestParseReferenceFollowsDockersGrammar(t *testing.T) {
	for _, bad := range []string{
		"x/../../containers/abc", "Upper", "a b", "", "app:", "app@sha256:short", "/abs",
	} {
		if _, err := ParseReference(bad); err == nil {
			t.Errorf("ParseReference(%q) accepted it", bad)
		}
	}
	for s, want := range map[string]string{
		"app":                     "docker.io/library/app:latest",
		"team/app:1.0":            "docker.io/team/app:1.0",
		"localhost:5000/x/y:z":    "localhost:5000/x/y:z",
		"public.ecr.aws/a/b:tag":  "public.ecr.aws/a/b:tag",
		"tule-functions-test:abc": "docker.io/library/tule-functions-test:abc",
	} {
		ref, err := ParseReference(s)
		if err != nil || ref.String() != want {
			t.Errorf("ParseReference(%q) = %v, %v; want %s", s, ref, err, want)
		}
	}
}
