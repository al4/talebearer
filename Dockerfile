# Build stage
FROM golang:1.11.5-alpine3.8 as builder

ENV CGO_ENABLED 0

RUN apk update && apk add curl git tar bash coreutils
SHELL ["/bin/bash", "-c"]

RUN curl -fsSlL -o /tmp/gometalinter.tgz https://github.com/alecthomas/gometalinter/releases/download/v3.0.0/gometalinter-3.0.0-linux-amd64.tar.gz && \
    sha256sum --quiet --check <<< "2cab9691fa1f94184ea1df2b69c00990cdf03037c104e6a9deab6815cdbe6a77 /tmp/gometalinter.tgz" && \
    tar -xvz --strip-components=1 -C /usr/local/bin -f /tmp/gometalinter.tgz

WORKDIR /src/talebearer

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -a --installsuffix cgo --ldflags="-s"

# Run tests
RUN go test -v ./...
# gometalinter, with a long deadline. Use shorter times (~60s) locally.
RUN gometalinter --deadline=240s --enable-gc --tests --aggregate --disable=gotype -e '^\.\./\.\.' --sort=path ./... || true

# Production image stage
FROM alpine:3.8

RUN apk --no-cache --update upgrade \
    && apk --no-cache add ca-certificates

COPY ["./ssl/*.crt", "/usr/local/share/ca-certificates/"]
RUN /usr/sbin/update-ca-certificates && \
    rm -rf /var/cache/apk/*

COPY --from=builder /src/talebearer/talebearer /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/talebearer"]
CMD ["-h"]
