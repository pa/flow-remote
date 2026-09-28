# The mailbox: API plus the phone app, for Cloud Run (linux/amd64).
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags=-s -o /mailbox ./cmd/mailbox

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /mailbox /mailbox
COPY web /web
ENV MAILBOX_WEB_DIR=/web
USER nonroot
ENTRYPOINT ["/mailbox"]
