.PHONY: test test-race pprof pprof-cpu-web pprof-mem-web

test:
	@go test -count 1000 -timeout 30s

test-race:
	@go test -race -timeout 45s

pprof:
	@go test -bench . -benchmem -cpuprofile cpu.pprof -memprofile mem.pprof

pprof-cpu-web:
	@go tool pprof -http=:8080 cpu.pprof

pprof-mem-web:
	@go tool pprof -http=:8080 mem.pprof