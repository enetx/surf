# Local Linux test environment

Build from the Surf module root. Docker provides Go, Node, Python, the C
toolchain, and packet-analysis tools without changing the host installation:

```sh
docker build -t surf-test:go1.27.4 -f tests/tools/Dockerfile .
docker run --rm \
  --mount type=bind,src="$(pwd)/..",dst=/work \
  --mount type=volume,src=surf-test-modules,dst=/go/pkg/mod \
  --mount type=volume,src=surf-test-build,dst=/root/.cache/go-build \
  surf-test:go1.27.4 go test -race -count=1 ./...
```

The parent mount supports the development `go.work` with sibling HTTP, QUIC,
and uTLS checkouts. Add `-e GOWORK=off` to verify published dependencies instead.
Module and build caches are separate persistent volumes. Rebuild the image when
updating tool versions; the image does not contain project source or credentials.

For capture work, mount a separate private output directory and add
`--cap-add=NET_ADMIN --cap-add=NET_RAW`. Install the exact official browser
version required by the experiment separately. Xvfb and NSS tools are included,
but no browser policy or certificate-verification override is enabled by this
image. Record actual tool versions in capture metadata. The browser runners and
their platform-specific executable paths are documented in
[wirecapture](wirecapture/README.md) and [echresumption](echresumption/README.md).

Raw pcaps, key logs, and browser profiles must stay outside the repository.
The ordinary regression suite and Node analyzer tests need no live browser or
packet-capture permissions.
