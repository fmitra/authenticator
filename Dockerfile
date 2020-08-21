FROM golang:1.15-alpine3.12 as builder
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
ENV PATH /authenticator:$PATH
