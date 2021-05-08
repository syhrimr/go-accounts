go-build:
	@go build -v -o go-accounts-app *.go

go-run:
	@./go-accounts-app

run:
	make go-build
	make go-run