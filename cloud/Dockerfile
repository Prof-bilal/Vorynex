# Vorynex Cloud control plane (ingestion API + dashboard).
#
# Build from the repository root, because the build needs go.mod and the engine:
#   docker build -f cloud/Dockerfile -t vorynex-cloud .
#
# The admin token is optional but recommended: without it the API is
# unauthenticated. Pass it as a secret, not as a layer:
#   docker run -p 8787:8787 -e VORYNEX_CLOUD_TOKEN=$(openssl rand -hex 32) vorynex-cloud
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY cloud ./cloud
COPY engine ./engine
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/vorynex-cloud ./cmd/vorynex-cloud

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl \
 && adduser -D -u 10001 vorynex
COPY --from=build /out/vorynex-cloud /usr/local/bin/vorynex-cloud
COPY cloud/dashboard /usr/share/vorynex/dashboard
COPY cloud/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
# The admin token is read from the environment at runtime; it is deliberately
# not declared with ENV/ARG so it never lands in an image layer.
ENV XDG_STATE_HOME=/var/lib/vorynex
RUN mkdir -p /var/lib/vorynex && chown vorynex:vorynex /var/lib/vorynex
USER vorynex
VOLUME /var/lib/vorynex
EXPOSE 8787
ENTRYPOINT ["/entrypoint.sh"]
