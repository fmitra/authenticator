FROM golang:1.12.1-alpine3.9 as builder
ENV GO111MODULE=on
WORKDIR /build-directory
COPY . .
RUN apk add --no-cache git
RUN apk add --update make
RUN make build

FROM gcr.io/distroless/base:latest
USER nobody
EXPOSE 8080
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /bin /authenticator
ENTRYPOINT ["./api"]
