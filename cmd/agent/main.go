package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/incodi404/logintel/config"
	rpchandler "github.com/incodi404/logintel/rpc_handler"
	"github.com/incodi404/logintel/utils"
	"github.com/incodi404/logintel/worker"
)

func main() {

	// signal from OS
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // if suddenly shut down

	// config
	if err := config.LoadConfig(); err != nil {
		fmt.Println(utils.Error("[ERROR] %w"), err)
		return
	}

	// RPC connection initialization
	conn, err := rpchandler.InitializeRPCConn("192.168.29.172:5051")
	if err != nil {
		fmt.Println(utils.Error("[ERROR] Error creating RPC connection: %w"), err)
	}
	defer conn.Close()

	// starting all the things
	worker.StartLogWorkerPool(ctx, conn)

	// block
	sigC := <-sigCh
	fmt.Printf("[MAIN] Terminating signal recieved: %s\n", sigC)
	fmt.Println("[MAIN] Shutting down...")

	// cancel()

	fmt.Println("[MAIN] Successfully terminated")
}
