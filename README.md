# bench_ecdsa_hmac

Run: 
```bash
go test -bench=. -benchtime=10000x
```

Results:
```
$ go test -bench=. -benchtime=10000x
goos: linux
goarch: amd64
pkg: bench_ecdsa_hmac
cpu: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
BenchmarkHMacSha256-8   	   10000	      2153 ns/op
BenchmarkEcdsaP256-8    	   10000	     27362 ns/op
PASS
ok  	bench_ecdsa_hmac	0.507s
```