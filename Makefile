test:
	@go test -count 1000 -timeout 30s

test-race:
	@go test -race -timeout 45s

pprof:
	@go test -cpuprofile cpu.pprof -memprofile mem.pprof -bench .

pprof-cpu-web:
	@go tool pprof -http=:8080 cpu.pprof

pprof-mem-web:
	@go tool pprof -http=:8080 mem.pprof