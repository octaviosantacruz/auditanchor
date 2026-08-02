# syntax=docker/dockerfile:1
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/auditanchor ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/auditanchor /auditanchor
USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/auditanchor"]
