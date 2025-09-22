FROM golang:1.21-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/authz ./cmd/server


FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=build /bin/authz /bin/authz
EXPOSE 8081
ENTRYPOINT ["/bin/authz"]