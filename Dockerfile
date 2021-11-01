# Build stage
FROM golang:1.17-alpine as builder

ARG GOLANGCI_LINT_VERSION=1.42.1
ENV CGO_ENABLED 0

RUN apk update && apk add curl git tar bash coreutils
SHELL ["/bin/bash", "-c"]

# Install GolangCI-Lint
RUN curl --fail --show-error --silent --location \
  "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-amd64.tar.gz" \
  | tar -xz --strip-components=1 -C /usr/bin/ "golangci-lint-${GOLANGCI_LINT_VERSION}-linux-amd64/golangci-lint"

WORKDIR /src/talebearer

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -a --installsuffix cgo --ldflags="-s"

# Run tests
RUN golangci-lint run --disable govet ./...
RUN go test -v ./...

# Production image stage
FROM alpine:3.12

RUN apk --no-cache --update upgrade \
    && apk --no-cache add ca-certificates

COPY ["./ssl/*.crt", "/usr/local/share/ca-certificates/"]
RUN /usr/sbin/update-ca-certificates && \
    rm -rf /var/cache/apk/*

COPY --from=builder /src/talebearer/talebearer /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/talebearer"]
CMD ["-h"]
