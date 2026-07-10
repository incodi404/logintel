package worker

import (
	"context"
	"fmt"
	"sync"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/incodi404/logintel/collector"
	dbusengine "github.com/incodi404/logintel/log_engines/dbus_engine"
	fileoperations "github.com/incodi404/logintel/log_engines/file_operations"
	"github.com/incodi404/logintel/models"
	"github.com/incodi404/logintel/streamer"
	"github.com/incodi404/logintel/utils"
	"google.golang.org/grpc"
)

func StartLogWorkerPool(ctx context.Context, conn *grpc.ClientConn) {
	// wg initialization
	var wg sync.WaitGroup

	// spin up every goroutines
	// shared error
	execErrCh := make(chan error, 500)
	execveErrCh := make(chan error, 500)
	isssErrCh := make(chan error, 500)
	connect4ErrCh := make(chan error, 500)
	bind4ErrCh := make(chan error, 500)
	fanotifyErrCh := make(chan error, 500)
	dbusErrCh := make(chan error, 500)

	Log_Error_Pipeline(ctx, &wg, execErrCh, "[EXEC]")
	Log_Error_Pipeline(ctx, &wg, execveErrCh, "[EXECVE]")
	Log_Error_Pipeline(ctx, &wg, isssErrCh, "[ISSS]")
	Log_Error_Pipeline(ctx, &wg, connect4ErrCh, "[CONNECT4]")
	Log_Error_Pipeline(ctx, &wg, bind4ErrCh, "[BIND4]")
	Log_Error_Pipeline(ctx, &wg, fanotifyErrCh, "[FANOTIFY]")
	Log_Error_Pipeline(ctx, &wg, dbusErrCh, "[DBUS]")

	// register all logs
	Start_Execve_Pipeline(ctx, &wg, execveErrCh, conn)
	Start_Exec_Pipeline(ctx, &wg, conn, execErrCh)
	Start_ISSS_Pipeline(ctx, &wg, isssErrCh, conn)
	Start_Connect4_Pipeline(ctx, &wg, connect4ErrCh, conn)
	Start_Bind4_Pipeline(ctx, &wg, bind4ErrCh, conn)
	Start_Fanotify_Pipeline(ctx, &wg, conn, fanotifyErrCh)
	Start_Dbus_Pipeline(ctx, &wg, conn, dbusErrCh)

	// closing err channel
	go func() {
		wg.Wait() // waiting for wg = 0
		close(execErrCh)
		close(execveErrCh)
		close(isssErrCh)
		close(connect4ErrCh)
		close(bind4ErrCh)
		close(fanotifyErrCh)
		close(dbusErrCh)
	}()
}

// Update Log_Error_Pipeline to accept a label
func Log_Error_Pipeline(ctx context.Context, wg *sync.WaitGroup, errCh <-chan error, label string) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case data, ok := <-errCh:
				if !ok {
					return
				}
				fmt.Printf("%s Error in pipeline: %v\n", label, data)
			}
		}
	}()
}

func Start_Exec_Pipeline(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn *grpc.ClientConn,
	errCh chan<- error,
) {
	// define the channel
	logCh := make(chan models.Exec_Log_Event_Decoded, 1000)

	// 2 wg for 2 goroutines
	wg.Add(2)

	// goroutines
	go func() {
		defer wg.Done()
		defer close(logCh)
		collector.Exec_Log_Collector(ctx, logCh, errCh)
	}()

	go func() {
		defer wg.Done()
		streamer.Exec_Streamer(ctx, logCh, errCh, conn)
	}()
}

func Start_Execve_Pipeline(
	ctx context.Context,
	wg *sync.WaitGroup,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {
	// define the channel
	logCh := make(chan models.PidInfo, 1000)

	// 2 wg for 2 goroutines
	wg.Add(2)

	// goroutines
	go func() {
		defer wg.Done()
		defer close(logCh)
		collector.Execve_Log_Collector(ctx, logCh, errCh)
	}()

	go func() {
		defer wg.Done()
		streamer.Execve_Streamer(ctx, logCh, errCh, conn)
	}()
}

func Start_ISSS_Pipeline(
	ctx context.Context,
	wg *sync.WaitGroup,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {
	logCh := make(chan models.ISSS_Network_Log_Event_Decoded, 1000)
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer close(logCh)
		collector.ISS_Log_Collector(ctx, logCh, errCh)
	}()

	go func() {
		defer wg.Done()
		streamer.ISSS_Streamer(ctx, logCh, errCh, conn)
	}()
}

func Start_Connect4_Pipeline(
	ctx context.Context,
	wg *sync.WaitGroup,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {
	logCh := make(chan models.Sock_Addr_Event_Decoded, 1000)
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer close(logCh)
		collector.Connect4_Log_Collector(ctx, logCh, errCh)
	}()

	go func() {
		defer wg.Done()
		streamer.Connect4_Streamer(ctx, logCh, errCh, conn)
	}()
}

func Start_Bind4_Pipeline(
	ctx context.Context,
	wg *sync.WaitGroup,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {
	logCh := make(chan models.Sock_Addr_Event_Decoded, 1000)
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer close(logCh)
		collector.Bind4_Log_Collector(ctx, logCh, errCh)
	}()

	go func() {
		defer wg.Done()
		streamer.Bind4_Streamer(ctx, logCh, errCh, conn)
	}()
}

func Start_Fanotify_Pipeline(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn *grpc.ClientConn,
	errCh chan<- error,
) {
	logCh := make(chan *models.FileOperationLog, 1000)

	fd, buf, err := fileoperations.FanotifyLogger()
	if err != nil {
		errCh <- fmt.Errorf("[FANOTIFY] Error ocuured in FanotifyLogger: %w", err)
		return
	}

	wg.Add(2)

	rule, err := utils.YamlProcessing[models.Fanotify_Filter_Rule]("./fanotify_filters.yaml")
	if err != nil {
		errCh <- fmt.Errorf("[FANOTIFY] Error ocuured in Fanotify rule loading: %w", err)
		return
	}

	go func() {
		defer wg.Done()
		defer close(logCh)
		fileoperations.Fanotify_Log_Collector(
			ctx,
			fd,
			rule,
			buf,
			logCh,
			errCh,
		)
	}()

	go func() {
		defer wg.Done()
		streamer.FanotifyStreamer(ctx, logCh, errCh, conn)
	}()
}

func Start_Dbus_Pipeline(
	ctx context.Context,
	wg *sync.WaitGroup,
	conn *grpc.ClientConn,
	errCh chan<- error,
) {
	logCh := make(chan *dbus.UnitStatus, 1000)

	wg.Add(2)

	go func() {
		defer wg.Done()
		defer close(logCh)
		dbusengine.SubscribeToSystemdServices(ctx, logCh, errCh)
	}()

	go func() {
		defer wg.Done()
		streamer.DbusUnitStreamer(ctx, logCh, errCh, conn)
	}()
}
