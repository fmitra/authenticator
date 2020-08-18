dev:
	cp config.example.json config.json

fmt:
	gofmt -w -s ./

lint:
	golangci-lint run -v

test:
	go test -v -race ./... -coverprofile=coverage.txt && go tool cover -func=coverage.txt

build:
	CGO_ENABLED=0 go build --ldflags "-s" -a -installsuffix cgo -o /bin/api ./cmd/api/
