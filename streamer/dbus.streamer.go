package streamer

import (
	"context"
	"fmt"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/incodi404/logintel/config"
	"github.com/incodi404/logintel/pb"
	"github.com/incodi404/logintel/utils"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func DbusUnitStreamer(
	ctx context.Context,
	collect <-chan *dbus.UnitStatus,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {
	// constructor
	client := pb.NewDbusUbitUploaderClient(conn)

	// stream ctx
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	agentId := config.ConfigValues.Token.AgentId // config

	// opening stream
	stream, err := client.DbusUnitUpload(streamCtx)
	if err != nil {
		errCh <- fmt.Errorf("[DBUS] Error opening stream: %w", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			_, err := stream.CloseAndRecv()
			if err != nil {
				errCh <- fmt.Errorf("[DBUS] Stream close has been failed: %w", err)
				return
			}
			return

		case log, ok := <-collect:
			if !ok {
				_, err := stream.CloseAndRecv()
				if err != nil {
					errCh <- fmt.Errorf("[DBUS] Stream close has been failed: %w", err)
					return
				}
				return
			}

			fmt.Println(utils.Info("[DBUS] Log received: "), log)
			uploadResult := &pb.DbusUnitLog{
				Timestamp:   timestamppb.Now(),
				Name:        log.Name,
				Description: log.Description,
				LoadState:   log.LoadState,
				ActiveState: log.ActiveState,
				SubState:    log.SubState,
				Followed:    log.Followed,
				Path:        string(log.Path),
				JobId:       log.JobId,
				JobType:     log.JobType,
				JobPath:     string(log.JobPath),
				AgentId:     agentId,
			}
			if err = stream.Send(uploadResult); err != nil {
				errCh <- fmt.Errorf("[DBUS] Streaming log error: %w", err)
				return
			}
		}
	}
}
