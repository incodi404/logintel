### E: Package 'bpftool' has no installation candidate

#### Solution:
1. sudo apt install linux-tools-common linux-tools-generic
2. sudo apt install linux-tools-$(uname -r)
3. bpftool version

=======================================================================================================

#### Generate object file
clang -O2 -g -target bpf -I /usr/include/x86_64-linux-gnu -c <program.c> -o <output.o>

=======================================================================================================

#### Package for gRPC in Golang

Plugins -
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

Runtime packages -
go get google.golang.org/protobuf
go get google.golang.org/grpc

=======================================================================================================
Problem: EXECVE hook is not working when we are trying to run EXEC and EXECVE parallaly with Goroutines. But working finely when only EXECVE is running.
Cause: handle_execve function is not attached when we are trying to run both. Only handle_exec is attached and that is why there was no logs.
Bug in code: We are running "defer loaded.Collection.Close()" as soon as the function returns rd so when another function is trying to fetch log with the rd, the main function has already closed and handle_execve is already unattached to kernel.
Fix: We moved defer loaded.Collection.Close()" to the collector. So now, the Link and Collection is closed when the log fetching is completed.