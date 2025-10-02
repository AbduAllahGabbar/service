FROM golang:1.21-alpine AS build
WORKDIR /src

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /bin/authz ./cmd/server

FROM alpine:3.18
RUN apk add --no-cache ca-certificates tini

RUN addgroup -S app && adduser -S -G app app
COPY --from=build /bin/authz /bin/authz
USER app
EXPOSE 8081
ENTRYPOINT ["/sbin/tini", "--", "/bin/authz"]