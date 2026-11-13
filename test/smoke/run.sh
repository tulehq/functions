#!/bin/sh
# Runs IMAGE the way users do and checks it works: the container must pass its
# own health check, run as the unprivileged user, reach the Docker daemon
# through the mounted socket, and serve signed requests: list the functions,
# and answer a function it does not have as Lambda does, kept in the store on
# its volume.
set -eu

image=${1:?usage: run.sh IMAGE}
name=functions-smoke-$$

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		docker logs "$name" || true
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT

# The nonroot user reaches the socket through its group.
socket=/var/run/docker.sock
gid=$(stat -c %g "$socket" 2>/dev/null || stat -L -f %g "$socket")

docker run -d --name "$name" -p 127.0.0.1::9060 -p 127.0.0.1::9061 \
	-v "$socket:/var/run/docker.sock" --group-add "$gid" \
	-e TULE_Auth_AccessKeyID=smoke -e TULE_Auth_SecretAccessKey=smoke \
	"$image" >/dev/null

# The health check first runs one interval (10s) after start.
health=
for _ in $(seq 60); do
	health=$(docker inspect -f '{{.State.Status}} {{.State.Health.Status}}' "$name")
	case $health in
	"running healthy") break ;;
	running*) sleep 1 ;;
	*) echo "container stopped: $health" >&2; exit 1 ;;
	esac
done
if [ "$health" != "running healthy" ]; then
	echo "container never became healthy: $health" >&2
	exit 1
fi

# The image must not run as root: it holds the store in its volume.
ids=$(docker exec "$name" id -u):$(docker exec "$name" id -g)
if [ "$ids" != 65532:65532 ]; then
	echo "runs as $ids, want 65532:65532" >&2
	exit 1
fi

addr=$(docker port "$name" 9060/tcp | head -n 1)

# Every call is a signed restJson1 request, which is what the Lambda API the
# SDKs speak looks like on the wire.
lambda() {
	curl -sS --aws-sigv4 aws:amz:us-east-1:lambda --user smoke:smoke \
		-o /dev/stdout -w ' %{http_code}' "$@"
}

listed=$(lambda "http://$addr/2015-03-31/functions")
case $listed in
*'"Functions":[]'*' 200') ;;
*)
	echo "listed functions $listed, want none" >&2
	exit 1
	;;
esac

missing=$(lambda "http://$addr/2015-03-31/functions/nope")
case $missing in
*'Function not found: arn:aws:lambda:us-east-1:000000000000:function:nope'*' 404') ;;
*)
	echo "got function nope $missing, want ResourceNotFoundException" >&2
	exit 1
	;;
esac

if ! docker exec "$name" test -s /data/functions.db; then
	echo "no store at /data/functions.db" >&2
	exit 1
fi

echo "smoke test passed: $image"
