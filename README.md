# functions

An AWS Lambda-compatible service that runs container-image functions
through Docker and triggers them from SQS queues. It is built to stand in
for Lambda in local development and end-to-end tests: point an AWS SDK at
it, create a function from an image Docker has, and invoke it
synchronously, asynchronously, or from a queue through an event source
mapping. Any image with a Lambda runtime interface client works: AWS's base
images, or your own `FROM scratch` image around an `aws-lambda-go` binary.

It is not a production compute service. Every access key it accepts shares
the same functions, and the functions run as plain Docker containers on the
daemon it is given. With [identity](https://github.com/tulehq/identity),
the keys identity issues are held to their identity policies
([below](#permissions)); standalone, the one configured key may do
everything.

## Running it

The service needs a Docker daemon: it creates, starts and removes the
function containers through the Docker Engine API, and the containers call
back into it on the Runtime API port, 9061.

With Docker, mounting the daemon's socket:

```sh
docker run --rm -p 9060:9060 -p 9061:9061 -v functionsdata:/data \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add "$(stat -c %g /var/run/docker.sock)" \
  -e TULE_Auth_AccessKeyID=test -e TULE_Auth_SecretAccessKey=test \
  ghcr.io/tulehq/functions:latest
```

The image is based on Alpine and runs as the unprivileged `nonroot` user,
which reaches the socket through the socket's group:

- **Linux:** `--group-add "$(stat -c %g /var/run/docker.sock)"`, the group
  that owns the socket on the host, as above. The smoke test runs the image
  this way.
- **Docker Desktop (macOS, Windows), unverified:** the socket a container
  sees is the one inside Docker Desktop's VM, and its group there is not the
  one `stat` reports on the Mac for `/var/run/docker.sock`. Mount it with
  `-v /var/run/docker.sock:/var/run/docker.sock` and give the group the
  socket has inside the VM, which `docker run --rm -v
  /var/run/docker.sock:/s ghcr.io/tulehq/functions:latest stat -c %g /s`
  would print; if the socket is owned by root with no group access, run the
  image with `--user root` instead. This setup has not been tried.

It keeps its database at `/data/functions.db` on the
`/data` volume, and its Docker health check polls `/_ready`. Port 9061 is
published because the function containers reach the Runtime API through
the Docker host (`host.docker.internal`), not through the service's own
container.

From source (Go 1.27.4 or later):

```sh
make build
TULE_Auth_AccessKeyID=test TULE_Auth_SecretAccessKey=test ./build/tule-functions
```

It listens on port 9060 for the Lambda API and on 9061 for the Runtime API,
beside the other Tule services: [object-store](https://github.com/tulehq/object-store)
on 9000, [secret-store](https://github.com/tulehq/secret-store) on 9010,
[accounts](https://github.com/tulehq/accounts) on 9020,
[identity](https://github.com/tulehq/identity) on 9030,
[mailbox](https://github.com/tulehq/mailbox) on 9040 and
[queues](https://github.com/tulehq/queues) on 9050.

### With queues, in Docker Compose

Event source mappings poll a queue over the SQS API. With
[queues](https://github.com/tulehq/queues) beside it, sharing the root key:

```yaml
services:
  queues:
    image: ghcr.io/tulehq/queues:0.1.0
    environment:
      TULE_Auth_AccessKeyID: test
      TULE_Auth_SecretAccessKey: test
    ports: ["9050:9050"]
    volumes: [queuesdata:/data]

  functions:
    image: ghcr.io/tulehq/functions:latest
    depends_on: [queues]
    environment:
      TULE_Auth_AccessKeyID: test
      TULE_Auth_SecretAccessKey: test
      TULE_Functions_QueuesEndpoint: http://queues:9050
    # The Runtime API port must be published on the same port number: the
    # function containers reach it as host.docker.internal:9061.
    ports: ["9060:9060", "9061:9061"]
    volumes:
      - functionsdata:/data
      - /var/run/docker.sock:/var/run/docker.sock
    # The group that owns the socket on the Docker host, such as
    # DOCKER_GID=$(stat -c %g /var/run/docker.sock).
    group_add: ["${DOCKER_GID}"]

volumes:
  queuesdata:
  functionsdata:
```

This file has not been run as written. The service calls queues at
`http://queues:9050` and signs with its own
root key, so both services must be configured with the same key (or
queues pointed at the same identity). The function containers are not on
the compose network: a function that calls queues itself reaches it as
`host.docker.internal:9050`, through the published port.

## Configuration

Settings come from environment variables prefixed with `TULE_`, and from a
`.env` file in the working directory (without the prefix).

| Variable | Default | Purpose |
|---|---|---|
| `TULE_Server_Port` | `9060` | The Lambda API's listen port |
| `TULE_Store_Path` | `./data/functions.db` (`/data/functions.db` in the image) | The SQLite database file of the functions, mappings and invocation history; it and its directory are created if missing |
| `TULE_Functions_DockerHost` | `unix:///var/run/docker.sock` | The Docker daemon: a `unix://` socket or a `tcp://host:port` |
| `TULE_Functions_RuntimeAPIHost` | `host.docker.internal` | The host the function containers reach the Runtime API at. With `host.docker.internal`, each container is given the `host.docker.internal:host-gateway` mapping, which a Linux daemon needs and Docker Desktop provides anyway |
| `TULE_Functions_RuntimeAPIPort` | `9061` | The Runtime API's listen port. `0` picks a free port |
| `TULE_Functions_RuntimeAPIBind` | unset (`0.0.0.0` in the image) | The IP address the Runtime API listens on. Unset, the address on the Docker host the containers reach it at, asked of Docker: `127.0.0.1` with Docker Desktop, which forwards `host.docker.internal` to the host's loopback, else the default bridge network's gateway, which `host-gateway` names. Set it when the containers reach the service some other way, such as `0.0.0.0` inside a container |
| `TULE_Functions_QueuesEndpoint` | unset | The SQS endpoint event source mappings poll, such as `http://localhost:9050`: an http or https URL. Unset, `CreateEventSourceMapping` is refused |
| `TULE_Functions_AccountID` | `000000000000` | The account ARNs carry: 12 digits |
| `TULE_Functions_Region` | `us-east-1` | The region ARNs carry, and the containers' `AWS_REGION` |
| `TULE_Functions_MaxContainers` | `10` | The most containers, and so invocations at once, per function. A container counts from its start until its removal completes, a retired one included |
| `TULE_Functions_MaxTotalContainers` | `50` | The most containers of every function together; at it, the least recently used idle container of another function is removed to make room |
| `TULE_Functions_PidsLimit` | `1024` | The most processes and threads a container may have, Lambda's quota |
| `TULE_Functions_IdleTimeout` | `10m` | How long a warm container may sit idle before it is removed |
| `TULE_Functions_PullImages` | `false` | Whether a function's image is pulled when Docker does not have it. Docker's container create never pulls, so with this off an image must be built or pulled into Docker first. A pull always names the tag (`latest` when the URI has neither a tag nor a digest) or the digest |
| `TULE_Functions_FunctionCredentials` | `role` with an identity endpoint, else `root` | The AWS credentials every container gets (`AWS_ACCESS_KEY_ID`, `AWS_ACCESS_KEY`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` for a role): `role`, a session of the function's execution role, assumed through identity, which needs `TULE_Auth_IdentityEndpoint`; `root`, the configured access key; `none`; or `custom`, the key below. See [Calling Tule services from a function](#calling-tule-services-from-a-function) |
| `TULE_Functions_FunctionAccessKeyID` | unset | With `custom`, the access key the containers get, such as one identity issued with narrower access; set only with `custom` |
| `TULE_Functions_FunctionSecretAccessKey` | unset | Its secret |
| `TULE_Functions_AsyncRetryDelay` | `1m` | The wait before an asynchronous invocation that failed runs again; the second retry waits twice this |
| `TULE_Functions_HistoryLimit` | `1000` | How many invocations the history keeps; the oldest go first |
| `TULE_Functions_HistoryMaxBytes` | `268435456` (256 MiB) | How many bytes of payloads, results and logs the history keeps together; the oldest go first, the newest is always kept. Each of an invocation's payload, result and log is cut at 1 MiB, ending in `...[truncated by tule]` |
| `TULE_HSTS_MaxAge` | unset | `Strict-Transport-Security` max age; the header is only sent when set |
| `TULE_Server_ReadTimeout` | `30s` | How long the server may take to read a request, body included |
| `TULE_Server_ReadHeaderTimeout` | `30s` | How long it may take to read a request's headers; must be positive |
| `TULE_Server_WriteTimeout` | `16m` | How long it may take to answer, from the end of the request's headers; it must hold a synchronous invocation of the longest timeout, 900 seconds |
| `TULE_Server_IdleTimeout` | `2m` | How long a keep-alive connection may sit idle between requests |
| `TULE_Server_ShutdownTimeout` | `7s` | How long a graceful shutdown waits for in-flight requests |
| `TULE_Auth_AccessKeyID` | required | The access key clients sign requests with, and the key the mappings sign their SQS calls with |
| `TULE_Auth_SecretAccessKey` | required | Its secret |
| `TULE_Auth_IdentityEndpoint` | unset | The identity service's base URL, such as `http://localhost:9030`. Set, the keys identity issued are accepted as well as the configured key, held to their identity policies, and identity is asked about them with the configured key, which must be identity's root key. Unset, functions runs standalone on the configured key alone and evaluates no policy |
| `TULE_GasEnv` | | `development` logs console output at trace level, `production` logs at warn level, `testing` disables logging |

The server refuses to start without an access key, because every request is
verified against it and any web page the developer has open can reach a
server on localhost; and when Docker does not answer at
`TULE_Functions_DockerHost`.

With an identity endpoint, a request signed with any key but the configured
one is verified through identity's signing-key endpoint, on every request.
When identity cannot be asked, fails, or gives no answer within 10 seconds,
such a request fails with `500` `ServiceException`, never as an unknown
key, and the configured key keeps working.

## Health checks

`GET /_health` (liveness) and `GET /_ready` (readiness) answer without a
signature. They respond `200` when every service reports healthy or ready and
`503` otherwise, with a JSON object of each service's status. Readiness fails
until the engine has started: the store's schema applied, the containers a
previous run left behind removed, and the mappings' pollers started.

## Connecting a client

Sign for the `lambda` service, in any region. The API is Lambda's restJson1
under `/2015-03-31/` and `/2017-03-31/tags/`, as the SDKs speak it. A
function ARN is `arn:aws:lambda:<region>:<account>:function:<name>`.

Go (AWS SDK v2):

```go
client := lambda.New(lambda.Options{
	Region:       "us-east-1",
	BaseEndpoint: aws.String("http://localhost:9060"),
	Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
})

_, err := client.CreateFunction(ctx, &lambda.CreateFunctionInput{
	FunctionName: aws.String("hello"),
	Role:         aws.String("arn:aws:iam::000000000000:role/lambda"),
	PackageType:  types.PackageTypeImage,
	Code:         &types.FunctionCode{ImageUri: aws.String("hello:latest")},
})
// Then wait for Active, as against Lambda:
err = lambda.NewFunctionActiveV2Waiter(client).Wait(ctx,
	&lambda.GetFunctionInput{FunctionName: aws.String("hello")}, time.Minute)
```

AWS CLI:

```sh
aws --endpoint-url http://localhost:9060 lambda invoke \
  --function-name hello --payload '{"name":"world"}' \
  --cli-binary-format raw-in-base64-out --log-type Tail out.json
```

A function image for local use can be as small as an `aws-lambda-go`
program and nothing else:

```dockerfile
FROM scratch
COPY bootstrap /bootstrap
ENTRYPOINT ["/bootstrap"]
```

built with `GOOS=linux GOARCH=$(go env GOARCH) CGO_ENABLED=0 go build -o
bootstrap` and `docker build -t hello:latest .`; building `FROM scratch`
pulls nothing.

## Supported operations

| Operation | Notes |
|---|---|
| `CreateFunction` | `PackageType` `Image` with `Code.ImageUri`; `ImageConfig` (`EntryPoint`, `Command`, `WorkingDirectory`), `Environment`, `Timeout` (1 to 900, default 3), `MemorySize` (128 to 10240, default 128), `Architectures` (default `x86_64`), `Description`, `Tags` and `Role`. Answers `201` with the function `Pending`; the image is checked in the background, and the function turns `Active`, or `Failed` with `StateReasonCode` `InvalidImage` and the reason when Docker does not have the image |
| `GetFunction` | The configuration, `Code` (`RepositoryType` `ECR`, `ImageUri`, `ResolvedImageUri`) and the tags |
| `GetFunctionConfiguration` | |
| `ListFunctions` | In creation order; `Marker` and `MaxItems` (1 to 10000, default 50) |
| `UpdateFunctionCode` | `ImageUri`, `Architectures`, `RevisionId`, `DryRun`. Answers with `LastUpdateStatus` `InProgress`; the new image is checked in the background and replaces the running one only when Docker has it, else the update is `Failed` and the function keeps running the old image. The function's containers are removed once it succeeds |
| `UpdateFunctionConfiguration` | `Environment` (replaced whole), `ImageConfig`, `Timeout`, `MemorySize`, `Description`, `Role`, `RevisionId`. Answers `InProgress`, then turns `Successful` at once; the containers are replaced as their invocations end |
| `DeleteFunction` | `204`. Removes the function's containers at once, those running an invocation included, and deletes its event source mappings |
| `Invoke` | `RequestResponse` (`200`, the function's result, or its error document with `X-Amz-Function-Error`), `Event` (`202`, run in the background with Lambda's retries) and `DryRun` (`204`). `LogType` `Tail` returns the last 4 KB of the log in `X-Amz-Log-Result`. `ClientContext` reaches the function as `Lambda-Runtime-Client-Context`. Payloads are JSON, up to 6 MB synchronous and 1 MB asynchronous; an empty payload is `{}` |
| `TagResource` / `UntagResource` / `ListTags` | On functions and event source mappings, by ARN; up to 50 tags |
| `CreateEventSourceMapping` | SQS queues only: `EventSourceArn`, `FunctionName`, `BatchSize` (default 10; up to 10000, 10 for a FIFO queue, more than 10 only with a batching window), `MaximumBatchingWindowInSeconds` (0 to 300), `Enabled`, `FunctionResponseTypes` (`ReportBatchItemFailures`), `ScalingConfig.MaximumConcurrency` (2 to 1000) and `Tags`. Refused when the function's timeout exceeds the queue's visibility timeout. Answers `202` `Creating`, then `Enabled` or `Disabled` |
| `GetEventSourceMapping` / `ListEventSourceMappings` | `ListEventSourceMappings` filters by `FunctionName` and `EventSourceArn`; `Marker` and `MaxItems` (default 100) |
| `UpdateEventSourceMapping` | The same members as create but the queue. Answers `202` `Updating`, then `Enabled` or `Disabled`; the visibility timeout is checked again |
| `DeleteEventSourceMapping` | `202` `Deleting`; the poller stops at once, and the mapping is then gone |

Any other path or method answers `404` `UnknownOperationException`.

Errors are Lambda's: the code in `X-Amzn-ErrorType`, and a body with `Type`
(`User` or `Service`) and the message under the member the SDK model gives
the error (`Message` for `ResourceNotFoundException`, `ServiceException`
and `ResourceInUseException`, `message` for the others). A function that
does not exist is `404` `ResourceNotFoundException`; an operation on a
`Pending` function, on one updating, or an invocation of a `Failed` one,
is `409` `ResourceConflictException`; a bad member is `400`
`InvalidParameterValueException`, or `ValidationException` for a value
outside the model's constraints; a mismatched `RevisionId` is `412`
`PreconditionFailedException`.

## Permissions

The configured key, and identity's root key, are the account's root user:
they are never evaluated against policies, as AWS never evaluates the root
user, and may call every operation. Root is the root user of the service's
own account, `TULE_Functions_AccountID`, only: a principal identity marks
as root in another account is treated as any principal of another account,
below. Without `TULE_Auth_IdentityEndpoint`
they are the only keys, so a standalone service evaluates nothing.

With it, every other key identity issued, an IAM user's or a role
session's, is evaluated on every request against the identity policies
identity sends with it (the user's inline and attached managed policies, or
the session's role's), with [tule.dev/policy](https://github.com/tulehq/policy):
an explicit `Deny` wins, otherwise the request needs an `Allow`. A request
no policy allows is `403` `AccessDeniedException`, the Lambda API's common
error, with AWS's message:

```
User: arn:aws:iam::000000000000:user/dev is not authorized to perform: lambda:GetFunction on resource: arn:aws:lambda:us-east-1:000000000000:function:hello because no identity-based policy allows the lambda:GetFunction action
```

or, for a `Deny`, "... on resource: \<arn\> with an explicit deny in an
identity-based policy". The operation is authorized before the function or
mapping is looked up, so a denied request on one that does not exist is
denied, not `404`.

Each operation is evaluated as the action and resource the
[Service Authorization Reference for Lambda](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awslambda.html)
gives it, in `internal/modules/lambda/actions.go`:

| Operation | Action | Resource |
|---|---|---|
| `CreateFunction` | `lambda:CreateFunction`, `iam:PassRole` on its `Role`, and `lambda:TagResource` with `Tags` | the function |
| `GetFunction`, `GetFunctionConfiguration`, `DeleteFunction`, `UpdateFunctionCode` | `lambda:` and the operation | the function |
| `UpdateFunctionConfiguration` | `lambda:UpdateFunctionConfiguration`, and `iam:PassRole` on a `Role` it sets | the function |
| `Invoke` | `lambda:InvokeFunction` | the function |
| `ListFunctions` | `lambda:ListFunctions` | `*` |
| `TagResource`, `UntagResource`, `ListTags` | `lambda:` and the operation | the function or mapping |
| `CreateEventSourceMapping` | `lambda:CreateEventSourceMapping`, and `lambda:TagResource` on the new mapping with `Tags` | `*` |
| `ListEventSourceMappings` | `lambda:ListEventSourceMappings` | `*` |
| `GetEventSourceMapping`, `UpdateEventSourceMapping`, `DeleteEventSourceMapping` | `lambda:` and the operation | the mapping |
| The retrieval API, `/_functions/` | `tule:Inspect` | `arn:aws:lambda:<region>:<account>:*` |

A function is `arn:aws:lambda:<region>:<account>:function:<name>`; a
mapping is `arn:aws:lambda:<region>:<account>:event-source-mapping:<UUID>`.
Both are rebuilt from the service's own partition, region and account and
the function or mapping the operation acts on, never taken from the
request: a `FunctionName` or tagging `Resource` ARN of another partition,
account or region names nothing here, and is `404`
`ResourceNotFoundException` before anything is evaluated.
`GetFunction`, `GetFunctionConfiguration`, `DeleteFunction` and `Invoke`,
the operations that take a qualifier, are evaluated on the function's ARN
with `:$LATEST` when the request names that qualifier, in its
`FunctionName` or `Qualifier`, since Lambda compares a policy's resource
with both. The other operations take none: `UpdateFunctionCode` and
`UpdateFunctionConfiguration` named `fn:$LATEST`, and the tagging
operations on a qualified ARN (tags apply to the function, not to versions
or aliases), are evaluated on the unqualified function ARN, and a
`Qualifier` query parameter they do not take is ignored. Lambda documents
no answer for a qualifier on those operations; this is the service's.

`GetFunction` returns a tagged function's `Tags` only to a caller allowed
`lambda:ListTags` on it, as the API reference says ("Lambda returns tag
data only if you have explicit allow permissions for lambda:ListTags"); to
anyone else it answers without them.
`iam:PassRole` is evaluated here, on the role's ARN with
`iam:PassedToService` `lambda.amazonaws.com`, against the caller's own
policies, as AWS evaluates it for the service the role is passed to.
`tule:Inspect` is Tule's own action, not AWS's: a principal that is not
root needs it to read or reset the invocation history.

The condition keys supplied are the global `aws:SourceIp` (the connection's
peer address), `aws:CurrentTime`, `aws:EpochTime`, `aws:SecureTransport`,
`aws:RequestedRegion` (the service's region, `TULE_Functions_Region`, not
the region a request is signed for: any signed region verifies, and the
request acts in the service's region, as an AWS endpoint fixes it),
`aws:PrincipalAccount`, `aws:PrincipalArn`, `aws:PrincipalType` and, for an
IAM user, `aws:username`; and the Lambda keys the reference lists:
`aws:ResourceTag/<key>` from the tags of the function or mapping acted on,
`aws:RequestTag/<key>` and `aws:TagKeys` from the tags `CreateFunction`,
`TagResource` and `CreateEventSourceMapping` set (`aws:TagKeys` from
`UntagResource`'s keys), and `lambda:FunctionArn` on the mapping
operations: the function the mapping invokes, and for an
`UpdateEventSourceMapping` that names another function, that one too, each
of which must be allowed. They fill policy variables such as
`${aws:username}` as well. A request whose condition keys pass the caps the
policy library asks services to apply (128 keys of at most 256 bytes, 50
values of a key, 1024 bytes a value) is refused with
`InvalidParameterValueException` rather than evaluated; Lambda's own limits
keep every valid request inside them. Every resource name a request gives is
held to Lambda's limit before anything is evaluated, since evaluation costs
grow with its length: a function name to 64 characters (`ValidationException`),
a tagging `Resource` to 256 (`ValidationException`) and a mapping's UUID to
a UUID (`ResourceNotFoundException`, as for any mapping that does not
exist), a `Role` to IAM's 2048 characters for an ARN (`ValidationException`;
the model gives `RoleArn` no length, so this limit is the service's), and
tag keys to 128 characters, `UntagResource`'s included.

The function an operation acts on is the one it was evaluated on: an
operation holds the function's name from authorization until it has acted,
and `CreateFunction` and `DeleteFunction` wait for it, so a function cannot
be deleted and created again under its name in between (an `Invoke` holds
it until the function to invoke is resolved, not while it runs). A
mapping's UUID is never reused, so it needs no such hold. What can change in
between is an attribute: a tag, or the function a mapping invokes, read at
authorization may be stale when the operation acts.

A request is decoded once, and authorized on the values the operation then
acts on: a JSON member given twice, or in two cases (`Role` and `role`),
or a query parameter given twice, resolves to one value, as Go's decoder
resolves it (the last member, the first parameter), for both.

Functions has no resource-based policies (`AddPermission` is not served),
so only identity policies decide.

**A principal of another account is denied every operation**, the
retrieval API included. In AWS a cross-account request needs a
resource-based policy that allows it as well as the caller's identity
policies, and here nothing can grant one; and since every account's keys
share the same functions, allowing it would let a member account's
administrator reach the management account's functions. Its identity
policies are evaluated first, so a `Deny` or a missing `Allow` is reported
as usual; when they allow the request, the message ends "because no
resource-based policy allows the \<action\> action". The service's account
is `TULE_Functions_AccountID`.

## How functions run

**Containers.** Each function's containers are created from the image ID
Docker resolved its image to when it was checked, with the function's
`ImageConfig` overriding the image's entry point, command and working
directory. A container's memory is the function's `MemorySize`, with no
swap; its processes and threads are bounded by `TULE_Functions_PidsLimit`;
Docker keeps its output with the `local` log driver, in one uncompressed
file of at most 10 MB, whatever the daemon's default driver is.

An invocation takes an idle container of the function's current
revision, or starts one while the function has fewer than
`TULE_Functions_MaxContainers` and the service fewer than
`TULE_Functions_MaxTotalContainers`; each container runs one invocation at
a time. A container counts against both caps from the moment it is
registered, before Docker creates it, until its removal completes, so
containers an update retires while they finish an invocation still count.
At a cap, a synchronous `Invoke` fails with `429`
`TooManyRequestsException`, as Lambda throttles; asynchronous and mapping
invocations wait for a container.

**Freezing.** Between invocations a container is paused, through Docker's
pause (the cgroup freezer), once its output has been collected, and thawed
before it is handed its next event, as Lambda freezes an execution
environment: what the function left running, such as a goroutine still
writing, does not run while the container is idle.

A container is removed when it has been
idle for `TULE_Functions_IdleTimeout`, when it times out, crashes or exits,
when its runtime does not ask for its next event within a second of
answering, when the function's code or configuration changes, and when the
function is deleted: at once, then, even while Docker is still creating it
or it is running an invocation. Every container carries the label
`dev.tule.functions.instance` with the store's own ID, so all of them are
removed on shutdown, and on the next start those a crashed run left behind.

**Environment.** A container has the function's variables and the ones
Lambda defines: `AWS_LAMBDA_RUNTIME_API`, `AWS_LAMBDA_FUNCTION_NAME`,
`AWS_LAMBDA_FUNCTION_MEMORY_SIZE`, `AWS_LAMBDA_FUNCTION_VERSION`
(`$LATEST`), `AWS_LAMBDA_INITIALIZATION_TYPE` (`on-demand`),
`AWS_LAMBDA_LOG_GROUP_NAME`, `AWS_LAMBDA_LOG_STREAM_NAME`, `AWS_REGION`,
`AWS_DEFAULT_REGION`, `LAMBDA_TASK_ROOT` and `LAMBDA_RUNTIME_DIR`, and the
credential variables Lambda sets from a function's role,
`AWS_ACCESS_KEY_ID`, `AWS_ACCESS_KEY`, `AWS_SECRET_ACCESS_KEY` and
`AWS_SESSION_TOKEN`: with `TULE_Functions_FunctionCredentials` `role` (the
default with identity), a session of the function's role
([below](#execution-roles)); with `root` (the default standalone) or
`custom`, the configured key or the custom one, with `AWS_SESSION_TOKEN`
unset, since the key is a static one. A function may not set the variables
the developer guide reserves, these included; the variables take at most 4
KB as JSON.

**Runtime API.** The containers speak Lambda's Runtime API, version
2018-06-01 (`invocation/next`, `invocation/{id}/response`,
`invocation/{id}/error`, `init/error`), with its headers: the request ID,
the deadline, the function ARN, an X-Ray trace header and the client
context. It is not signed. It listens only on `TULE_Functions_RuntimeAPIBind`;
a request's headers must arrive within 10 seconds and a response's or
error's body within a minute, while `invocation/next` may wait for as long
as there is no event, and a connection may sit idle for as long as its
paused container may. Each container gets its own random token as a
path prefix, `AWS_LAMBDA_RUNTIME_API=host.docker.internal:9061/<token>`,
and a request is served by that container's session only, so one container
cannot read another's events or answer for it. A response or error for a
request the container is not running is `400`.

**Outcomes.** A runtime's error document is answered as it sent it, with
`X-Amz-Function-Error: Unhandled`; a container that exits before answering
is `Runtime.ExitError`; an invocation that runs past its timeout is
stopped, its container removed, and answered with
`{"errorType":"Sandbox.Timedout","errorMessage":"RequestId: <id> Error:
Task timed out after 3.00 seconds"}`. A runtime has 10 seconds to
initialize, from its container's start to its first `invocation/next`.

**Logs.** An invocation's log is its container's stdout and stderr as Docker
streams them, in Lambda's plain text format: the output before the
invocation (a cold start's initialization), `START RequestId: <id>
Version: $LATEST`, the invocation's output, `END RequestId: <id>`, and
`REPORT RequestId: <id>` with `Duration`, `Billed Duration`, `Memory Size`,
`Init Duration` on a cold start, and `Status: timeout` for a timeout, which
also logs `Task timed out after N seconds`. An invocation's log keeps the
first 1 MiB of its output, and says how many more bytes it dropped.

**Asynchronous invocations.** `Event` invocations are queued in memory and
run in the background. One that fails or times out runs again after
`TULE_Functions_AsyncRetryDelay` (1 minute) and after twice that, Lambda's
default of two retries, under the same request ID. One that cannot run at
all, because the function is not ready or its container would not start,
is retried with backoff from 1 second to 5 minutes for up to 6 hours,
Lambda's default maximum event age; when the function is deleted, or the
event ages out, it is recorded in the history as `failed`, with the error
that stopped it.

## Calling Tule services from a function

Lambda gives a function its role's credentials, so the function's SDK can
call other services. With identity, so does this service, by default
([Execution roles](#execution-roles)): the function's SDK has exactly what
its role's policies allow, at every Tule service pointed at the same
identity.

Standalone there are no roles, and every function gets the configured
access key, `TULE_Auth_AccessKeyID` and its secret
(`TULE_Functions_FunctionCredentials=root`). **Function code then runs
with that key's full access**: it is the root key, which every Tule service
configured with it accepts for every operation, this service's included.
Run only code you trust. `root` and `custom` can be chosen with identity
too, as explicit settings, and the service then logs a warning at startup:
**any principal allowed `lambda:CreateFunction` or
`lambda:UpdateFunctionCode`, and `lambda:InvokeFunction`, can run code that
reads that key, and so obtain its access** whatever its own policies say.

Since the credential variables are reserved, as on Lambda, a function's own
`Environment` cannot replace them. To give the functions one narrower key,
such as one identity issued to a user with no more access than they need,
set `TULE_Functions_FunctionCredentials=custom` with
`TULE_Functions_FunctionAccessKeyID` and
`TULE_Functions_FunctionSecretAccessKey`; `none` gives them no
credentials.

To make a function's SDK call Tule rather than AWS, set the service
endpoint variables the AWS SDKs read in the function's own `Environment`;
Lambda does not reserve them. Each is `AWS_ENDPOINT_URL_` and the service's
SDK ID, upper case with spaces as underscores, as the Go SDK's
`config.LoadDefaultConfig` forms it; `AWS_ENDPOINT_URL` sets one for every
service. The containers reach the other services through the Docker host,
on their published ports:

```sh
aws --endpoint-url http://localhost:9060 lambda update-function-configuration   --function-name hello --environment 'Variables={
    AWS_ENDPOINT_URL_S3=http://host.docker.internal:9000,
    AWS_ENDPOINT_URL_SQS=http://host.docker.internal:9050,
    AWS_ENDPOINT_URL_SES=http://host.docker.internal:9040,
    AWS_ENDPOINT_URL_SESV2=http://host.docker.internal:9040}'
```

`AWS_ENDPOINT_URL_SES` is the SES v1 clients'; the SES v2 clients, which
mailbox serves, read `AWS_ENDPOINT_URL_SESV2`. `host.docker.internal`
resolves in the containers on Docker Desktop, and on Linux through the
host-gateway mapping the service adds when `TULE_Functions_RuntimeAPIHost`
is `host.docker.internal`, its default.

## Execution roles

With `TULE_Functions_FunctionCredentials=role`, the default when
`TULE_Auth_IdentityEndpoint` is set, a function runs with its execution
role, the `Role` it was created or updated with, as on Lambda:

- **Each container gets a session of the role.** When a container starts,
  the role is assumed through identity's assume-role endpoint
  ([tule.dev/identity/servicerole](https://github.com/tulehq/identity)),
  signed with the root key, as `lambda.amazonaws.com`, with the function's
  ARN as `aws:SourceArn` and its account as `aws:SourceAccount`, for
  identity's default hour. The session is named after the function, so its
  ARN is `arn:aws:sts::<account>:assumed-role/<role>/<function>`, the form
  Lambda's sessions have; a one-character function name is padded with `_`,
  since a session name is at least two characters. The container gets the
  session as `AWS_ACCESS_KEY_ID`, `AWS_ACCESS_KEY`, `AWS_SECRET_ACCESS_KEY`
  and `AWS_SESSION_TOKEN`.
- **No invocation runs with expired credentials.** A warm container is
  reused only while its session has the function's timeout and a minute
  left; otherwise it is removed and a new container, with a new session,
  takes the invocation. A container's session cannot be swapped while it
  runs, as environment variables are fixed, so a container lasts at most
  about an hour.
- **The role must trust Lambda.** Its trust policy must allow
  `lambda.amazonaws.com` `sts:AssumeRole`, as the Lambda Developer Guide's
  execution role does:

  ```json
  {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
  ```

  `CreateFunction`, and `UpdateFunctionConfiguration` with a `Role`, assume
  the role once to check it, and a role that does not exist or does not
  trust Lambda is refused as Lambda refuses it: `400`
  `InvalidParameterValueException`, "The role defined for the function
  cannot be assumed by Lambda." A role that stops trusting Lambda later, or
  is deleted, makes the function's next cold start fail with `500`
  `ServiceException`.
- **Mappings poll with the role.** A mapping's poller signs its SQS calls
  with a session of its function's execution role, as Lambda polls with it,
  so the role needs the permissions the Lambda Developer Guide gives a
  mapping's role, those of the `AWSLambdaSQSQueueExecutionRole` managed
  policy, `sqs:ReceiveMessage`, `sqs:DeleteMessage` and
  `sqs:GetQueueAttributes`, and here also `sqs:GetQueueUrl`, with which the
  poller finds the queue by name. Identity ships no such managed policy;
  put them in a policy of the role. `CreateEventSourceMapping` and
  `UpdateEventSourceMapping` read the queue's visibility timeout with the
  role too, so a role that cannot be assumed or read the queue is refused
  there with `InvalidParameterValueException`. A role changed on the
  function is polled with within a minute.
- **The role is of the service's account.** A `Role` of another account is
  refused on `CreateFunction` and `UpdateFunctionConfiguration`, before
  anything is evaluated, for every caller, the root key included, and in
  every credentials mode, as Lambda refuses it: `403`
  `AccessDeniedException`, "Cross-account pass role is not allowed.", since
  `iam:PassRole` passes a role only within its account. A role that is not
  of the `aws` partition, or whose ARN does not name a `role/`, is
  `ValidationException` against the model's `RoleArn` pattern. A function
  stored with such a role before this check is never given its session:
  its container start fails as for a role Lambda cannot assume.
- **The role read is the one acted on.** A container's session is of the
  role of the very function revision it runs, and a configuration update
  that changes the `Role` makes a new revision, whose containers replace the
  old ones.

With `root`, `custom` or `none`, the `Role` is checked against the model's
pattern, recorded and passed with `iam:PassRole`, never assumed, and the
pollers sign with the configured key.

## Event source mappings

Each enabled mapping runs a poller that calls the queue over the SQS API,
with the AWS SDK's SQS client, at `TULE_Functions_QueuesEndpoint`, signed
with its function's execution role ([above](#execution-roles)), or with the
configured key unless the functions run with their roles: Tule's queues
service or SQS itself. It runs five
batches at once, or `ScalingConfig.MaximumConcurrency`. It long polls for
20 seconds, gathers up to `BatchSize` messages for up to the batching
window after the first arrives (a FIFO queue's batch is one receive's), and
invokes the function synchronously with the event Lambda builds:

```json
{"Records": [{
  "messageId": "059f36b4-87a3-44ab-83d2-661975830a7d",
  "receiptHandle": "AQEB...",
  "body": "hello",
  "attributes": {"ApproximateReceiveCount": "1", "SentTimestamp": "1794539309572",
                 "SenderId": "000000000000", "ApproximateFirstReceiveTimestamp": "1794539309590"},
  "messageAttributes": {"kind": {"stringValue": "greeting", "stringListValues": [],
                                 "binaryListValues": [], "dataType": "String"}},
  "md5OfBody": "5d41402abc4b2a76b9719d911017c592",
  "eventSource": "aws:sqs",
  "eventSourceARN": "arn:aws:sqs:us-east-1:000000000000:orders",
  "awsRegion": "us-east-1"
}]}
```

`attributes` are every system attribute the queue reports; a FIFO queue's
carry `MessageGroupId`, `MessageDeduplicationId` and `SequenceNumber`. A
binary attribute value is base64.

When the invocation succeeds, the batch is deleted. With
`ReportBatchItemFailures`, everything but the messages the function names in
`{"batchItemFailures": [{"itemIdentifier": "<messageId>"}]}` is deleted; a
response that is not a JSON object, or names an empty, null or unknown
`itemIdentifier`, fails the whole batch, and an empty or null response or
list fails nothing, as the developer guide gives the rules. When the
invocation fails or times out, nothing is deleted: the messages become
visible again after the queue's visibility timeout, and move to its
dead-letter queue once its redrive policy says. A FIFO queue's groups keep
their order, since the queue holds a group while any of its messages is in
flight. `LastProcessingResult` is `No records processed`, `OK`, or
`PROBLEM: Function call failed`.

## Retrieval API

Beside Lambda's API, the service answers JSON routes under `/_functions/`
that are not AWS's: to read back the invocations it ran, and to reset the
history between tests. They are signed like every other request, for the
`lambda` service, and need the root key or a principal allowed
`tule:Inspect` on `arn:aws:lambda:<region>:<account>:*`
([Permissions](#permissions)).

| Route | Answer |
|---|---|
| `GET /_functions/invocations` | `200` with `{"items": [invocation, ...], "nextCursor": "..."}`, newest first. `function`, `status` (`succeeded`, `failed`, `timedOut`), `source` (`invoke`, `async`, `eventSourceMapping`), `since` and `until` (RFC 3339, inclusive) filter it; `limit` is 1 to 100, 20 by default; `cursor` takes the `nextCursor` of the page before, which the last page leaves out |
| `GET /_functions/invocations/{requestId}` | `200` with the invocation, its `payload`, its `result` and its whole `log` |
| `DELETE /_functions/invocations` | `204`: empties the history |

An invocation is:

```json
{
  "requestId": "3f1c8a52-8f4e-4c39-9a0b-1d6c0b2f7a11",
  "function": "hello",
  "time": "2026-11-13T03:08:29.572Z",
  "source": "invoke",
  "status": "failed",
  "duration": 12.34,
  "attempts": 1,
  "errorType": "errorString",
  "errorMessage": "the handler failed",
  "payload": "{\"name\":\"world\"}",
  "result": "{\"errorMessage\":\"the handler failed\",\"errorType\":\"errorString\"}",
  "log": "START RequestId: ...\n...REPORT RequestId: ...\n"
}
```

`time` is when the invocation started, RFC 3339 in UTC to the millisecond;
`duration` is in milliseconds; `errorType` and `errorMessage` are empty for
a success. `payload` and `result` are the bytes as text, and only the item
read back by its request ID carries them and the log. An asynchronous
invocation is one item, its last attempt, with `attempts` counting them; a
mapping's batch is one item of its own request ID.

An error is `{"code", "message"}` with the code in `X-Amzn-ErrorType`: `404`
`ResourceNotFoundException` for an unknown request ID, `400`
`InvalidParameterValueException` for a bad filter, `limit` or `cursor`,
`403` `AccessDeniedException` without `tule:Inspect`, and the signature
errors of the Lambda API.

```sh
curl -fsS --aws-sigv4 aws:amz:us-east-1:lambda --user test:test \
  'http://localhost:9060/_functions/invocations?function=hello&status=failed'

curl -fsS --aws-sigv4 aws:amz:us-east-1:lambda --user test:test \
  -X DELETE http://localhost:9060/_functions/invocations
```

## Differences from AWS

- **Identity policies only.** Keys identity issued are held to their
  identity policies; resource-based policies, permissions boundaries,
  session policies and SCPs are not part of evaluation, and functions has
  no function policies to store. Every accepted key works on the same
  functions. `Role` is checked against the model's pattern, passed with
  `iam:PassRole`, and assumed with the functions' role credentials
  ([Execution roles](#execution-roles)); with any other credentials it is
  recorded and never assumed, and whether a role of that ARN exists is not
  checked.
- **Duplicate tag keys are refused.** A request that names a tag key
  twice, or has two `Tags` members, is refused with
  `InvalidParameterValueException`, since JSON decoding would keep one
  silently. For a principal that is evaluated, so is a request that names
  two keys that differ only in case, or one that differs only in case from
  a key the resource has: the policy library matches condition keys without
  regard to case, so `Team` and `team` would be one `aws:RequestTag/team`
  or `aws:ResourceTag/team` with two values. The root key may still set
  them, and a request of an evaluated principal on a resource that holds
  such keys fails with `500` `ServiceException` rather than be evaluated.
  Lambda documents no answer for these requests; these are the service's.
- **Some condition keys are not supplied.** `aws:PrincipalArn` of a role
  session is its role's ARN without the role's path, which AWS includes:
  the session's ARN carries no path and identity does not send it yet. **A
  policy condition on a role ARN that includes a path does not match a
  session**, so a `Deny` written that way, such as one on
  `arn:aws:iam::*:role/restricted/*`, does not apply to sessions yet; write
  it on the path-less role ARN until identity sends the path. `aws:userid` (the principal's
  unique ID) and `aws:PrincipalTag/<key>` are not supplied, since identity
  does not send them; nor are `lambda:Layer`, `lambda:VpcIds`,
  `lambda:SubnetIds`, `lambda:SecurityGroupIds` and
  `lambda:CodeSigningConfigArn`, for features the service does not have,
  and `lambda:EventSourceToken` and `lambda:InvokedViaFunctionUrl`.
- **A function's role session is refreshed by replacing its container.**
  Lambda's runtime keeps an execution environment's credentials valid;
  here a container keeps the session it started with, and is replaced
  before the session would expire during an invocation. Standalone, or with
  `root` or `custom`, a function gets one configured key instead of its
  role's, with no session token, and function code has that key's full
  access; `none` gives it none.
- **Container images only.** `PackageType` `Zip`, which is also what a
  request without a `PackageType` asks for, is refused with
  `InvalidParameterValueException`, as an unsupported value is; so are
  `Runtime` and `Handler`. `ImageUri` is any reference in Docker's grammar,
  `name[:tag][@digest]`, not only an ECR one; anything else is refused with
  `InvalidParameterValueException`. `GetFunction` reports `RepositoryType` `ECR` all the
  same, and `CodeSha256` is the image's repository digest, or its image ID
  for an image built locally; `CodeSize` is 0.
- **Images are not pulled unless asked.** Docker's container create never
  pulls, so a function whose image Docker does not have turns `Failed`
  with `InvalidImage`, unless `TULE_Functions_PullImages` is set. A
  `Failed` function can be given a working image with `UpdateFunctionCode`,
  where Lambda wants it deleted and created again.
- **Only `$LATEST`.** There are no versions, aliases, layers, reserved or
  provisioned concurrency, function URLs, SnapStart, VPC, file systems,
  dead-letter queues, destinations or event invoke configs. `Publish` is
  ignored; a `Qualifier` other than `$LATEST` names no function.
- **`MemorySize` is enforced; `Architectures` is recorded, not
  enforced.** A container gets `MemorySize` of memory and no swap, and is
  killed by Docker past it, rather than failing as Lambda reports it. It
  runs on the Docker daemon's architecture whatever the function says. CPU
  is not scaled with memory.
- **Concurrency is a per-function cap of containers**,
  `TULE_Functions_MaxContainers`, under a cap for the service,
  `TULE_Functions_MaxTotalContainers`, rather than an account's pool. Over
  them, a synchronous `Invoke` is throttled with `429`
  `TooManyRequestsException` (`Rate Exceeded.`); asynchronous and mapping
  invocations wait.
- **Asynchronous invocations live in memory.** A queued or retrying one is
  lost when the service stops. There is no on-failure destination or
  dead-letter queue, and the maximum event age is Lambda's default, 6
  hours, not configurable; the function error retry delays are
  `TULE_Functions_AsyncRetryDelay` and twice it, Lambda's 1 and 2 minutes
  by default.
- **Updates are near-instant.** `UpdateFunctionConfiguration` reports
  `InProgress` and completes at once; `TagResource` is not refused while an
  update is in progress.
- **`DeleteFunction` deletes the function's event source mappings.**
- **The Runtime API address carries a path.** `AWS_LAMBDA_RUNTIME_API` is
  `host:port/<token>`, which runtime clients that append the API path to
  it, as `aws-lambda-go` does, accept. A client that parses it as a bare
  host and port does not work.
- **`X-Amz-Function-Error` is always `Unhandled`**, which is what Lambda
  reports for an error a runtime posts, a crash and a timeout.
- **A runtime gets 10 seconds to initialize**, Lambda's on-demand init
  limit, separately from the function's timeout; an init that runs past it
  is reported as `Sandbox.Timedout` after 10 seconds. There is no
  suppressed init.
- **Logs are kept in the history, not CloudWatch.** `AWS_LAMBDA_LOG_GROUP_NAME`
  and `AWS_LAMBDA_LOG_STREAM_NAME` are set but nothing is behind them. The
  `REPORT` line has no `Max Memory Used` and no X-Ray fields.
- **Output is attributed by when it arrives.** Docker streams a container's
  stdout and stderr on its own schedule, with nothing that orders them
  against the container's Runtime API requests, so after a response the
  service waits for the runtime's next request and then until the output
  has been quiet for 25 ms, up to 500 ms, before it pauses the container
  and closes the invocation's log. Output a function writes after it
  answers lands in that invocation's log while the drain lasts, and is
  frozen after it; output written after the container thaws for the next
  invocation is that invocation's.
- **Validation messages are close to Lambda's, not always the same.** The
  codes and statuses are the model's; `ValidationException` messages name
  the member and the constraint in Lambda's form.
- **SQS mappings only, without filtering or provisioned mode.**
  `StartingPosition` is refused. The poller runs five batches at once (or
  `MaximumConcurrency`) and does not scale with the backlog. The function's
  timeout is checked against the queue's visibility timeout when a mapping
  is created or updated, as the developer guide says Lambda does, and not
  when the function's timeout changes later.
- **The history is bounded**, to `TULE_Functions_HistoryLimit` invocations
  and `TULE_Functions_HistoryMaxBytes` of their payloads, results and logs,
  each of those cut at 1 MiB.
- **A mapping's batch is cut to fit the payload limit.** A batch whose
  event would pass 6 MB (6291456 bytes) is split, in order, into the
  batches that fit, each invoked and deleted on its own, as Lambda passes
  fewer records than the batch size when they would not fit.
- **A shutdown ends the invocations in flight.** When the service begins to
  stop, synchronous invocations fail with `500` `ServiceException` and
  every container is removed, so a stop does not wait out a function's
  timeout.
- **Docker Engine API 1.41 or later** (Docker 20.10) is required; the
  service refuses to start against an older daemon.
- **The retrieval API returns a payload and a result as text**, the bytes
  as the caller and the function sent them, not as JSON values.
- **The image runs as `nonroot`**, so it needs the Docker socket's group;
  the Docker Desktop setup above is unverified.
- **Logs record the connection's peer address.** `X-Forwarded-For` is not
  trusted, since nothing is expected in front of this service and the header
  is unsigned.

## Development

```sh
make test       # unit tests; the runner's and the app's run containers on the local Docker
make test-e2e   # end-to-end tests: the app in-process, driven by the AWS SDK, on real Docker
make lint
make image      # build ghcr.io/tulehq/functions:dev
make smoke      # build the image, run it, and check it serves signed requests
make push VERSION=0.1.0   # build for amd64 and arm64 and push
```

The tests build their function images `FROM scratch` around Go programs
built with `aws-lambda-go` for Linux on the host's architecture
(`internal/testfn` for the unit tests, `test/e2e/testdata` for the
end-to-end tests), so they pull nothing, and remove the images and
containers they create.

The end-to-end tests include ones against a real identity service and a
real queues service, built from their checkouts and run as processes: the
siblings `../identity` and `../queues` by default, or the directories
`TULE_E2E_IDENTITY_DIR` and `TULE_E2E_QUEUES_DIR` name. The execution role
tests also run a real object-store, at `../object-store` or
`TULE_E2E_OBJECT_STORE_DIR`, which holds the role sessions to their
policies. CI checks out `tulehq/identity` v0.4.0, `tulehq/queues` v0.2.0
and `tulehq/object-store` v0.6.0 and sets them.

## Upgrading from v0.1

This release is a breaking one with identity: **identity-issued keys are
held to their identity policies.** In v0.1 every key identity issued could
call every operation and the retrieval API; now a key whose user or role
has no policy allowing an action is denied it with `AccessDeniedException`,
so a key that worked with no policy loses access. Give each user or role
the policies it needs, such as `lambda:*` and `iam:PassRole` on the
functions' roles, and `tule:Inspect` for the retrieval API. It needs
identity v0.3.1, which sends the policies and assumes the execution roles;
v0.1.0 cannot send policies, and its keys are refused with `500`
`ServiceException`.

**With identity, functions run with their execution roles** by default.
Each function's `Role` must now be a role identity has, whose trust policy
allows `lambda.amazonaws.com`, or `CreateFunction` refuses it; an existing
function whose role does not is not refused until it next starts a
container, which then fails. The containers get the role's session, not
the root key, so a function needs a role whose policies allow what its code
calls, and a mapping's function's role needs the SQS permissions above. Set
`TULE_Functions_FunctionCredentials=root` to keep v0.1's root key.
Standalone use, with no identity endpoint, is unchanged.

## License

[MIT](LICENSE)
