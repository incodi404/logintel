protoc -I=../protos --go_out=../pb --go_opt=paths=source_relative ../protos/dbus.proto
protoc -I=../protos --go-grpc_out=../pb --go-grpc_opt=paths=source_relative ../protos/dbus.proto

protoc -I=../protos --go_out=../pb --go_opt=paths=source_relative ../protos/exec.proto
protoc -I=../protos --go-grpc_out=../pb --go-grpc_opt=paths=source_relative ../protos/exec.proto

protoc -I=../protos --go_out=../pb --go_opt=paths=source_relative ../protos/execve.proto
protoc -I=../protos --go-grpc_out=../pb --go-grpc_opt=paths=source_relative ../protos/execve.proto

protoc -I=../protos --go_out=../pb --go_opt=paths=source_relative ../protos/fanotify.proto
protoc -I=../protos --go-grpc_out=../pb --go-grpc_opt=paths=source_relative ../protos/fanotify.proto

protoc -I=../protos --go_out=../pb --go_opt=paths=source_relative ../protos/network.proto
protoc -I=../protos --go-grpc_out=../pb --go-grpc_opt=paths=source_relative ../protos/network.proto