package rpchandler

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func InitializeRPCConn(url string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		url,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return &grpc.ClientConn{}, fmt.Errorf(
			"Error creating new connection for log stream: %w", err,
		)
	}

	return conn, nil
}
