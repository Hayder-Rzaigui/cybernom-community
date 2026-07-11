# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod ./
COPY go.sum* ./
RUN go mod download

COPY . .
RUN go mod tidy && go mod verify

# CGO disabled -> fully static binary, smaller final image, no libc dependency
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/cybernom \
    ./cmd/cybernom

# ---- final stage ----
FROM gcr.io/distroless/static-debian12:nonroot

# distroless nonroot image: no shell, no package manager, runs as uid 65532.
# This substantially shrinks the attack surface compared to a full alpine
# runtime image — there is nothing in this image an attacker could use to
# pivot even with arbitrary code execution inside the container.

COPY --from=builder /out/cybernom /usr/local/bin/cybernom
COPY config/config.yaml.example /etc/cybernom/config.yaml
COPY migrations /etc/cybernom/migrations

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/cybernom", "-config", "/etc/cybernom/config.yaml"]
