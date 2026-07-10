package streamer

import (
	"context"
	"fmt"

	"github.com/incodi404/logintel/config"
	"github.com/incodi404/logintel/models"
	"github.com/incodi404/logintel/pb"
	"github.com/incodi404/logintel/utils"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func FanotifyStreamer(
	ctx context.Context,
	collect <-chan *models.FileOperationLog,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {
	// constructor
	client := pb.NewFanotifyUploaderClient(conn)

	// stream ctx
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	agentId := config.ConfigValues.Token.AgentId // config

	// opening stream
	stream, err := client.FanotifyUpload(streamCtx)
	if err != nil {
		errCh <- fmt.Errorf("[FANOTIFY] Error opening stream: %w", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			_, err := stream.CloseAndRecv()
			if err != nil {
				errCh <- fmt.Errorf("[FANOTIFY] Stream close has been failed: %w", err)
				return
			}
			return

		case log, ok := <-collect:
			if !ok {
				_, err := stream.CloseAndRecv()
				if err != nil {
					errCh <- fmt.Errorf("[FANOTIFY] Stream close has been failed: %w", err)
					return
				}
				return
			}

			fmt.Println(utils.Info("[FANOTIFY] Log received: "), log)
			if log != nil {
				uploadResult := &pb.FanotifyLog{
					Timestamp:     timestamppb.Now(),
					Pid:           int64(log.Pid.Pid),
					Name:          log.Pid.Name,
					Comm:          log.Pid.Cmd,
					ParentProcess: int64(log.Pid.ParentProcess),
					Path:          log.Path,
					Events:        log.Events,
					AgentId:       agentId,
				}
				if err = stream.Send(uploadResult); err != nil {
					errCh <- fmt.Errorf("[EXECVE] Streaming log error: %w", err)
					return
				}
			}
		}
	}
}
