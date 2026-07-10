package streamer

import (
	"context"
	"fmt"
	"time"

	"github.com/incodi404/logintel/config"
	"github.com/incodi404/logintel/models"
	"github.com/incodi404/logintel/pb"
	"github.com/incodi404/logintel/utils"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Execve_Streamer(
	ctx context.Context,
	logData <-chan models.PidInfo,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {

	// generate constructor
	client := pb.NewExecveLogUploaderClient(conn)

	// timeout
	// streamCtx, cancel := context.WithTimeout(ctx, 10*time.Second) // This is breaking the stream with EOF
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	agentId := config.ConfigValues.Token.AgentId // config

	// open stream
	stream, err := client.ExecveUpload(streamCtx)
	if err != nil {
		errCh <- fmt.Errorf(
			"Opening Execve stream failed: %w", err,
		)
		return
	}

	for {
		select {
		case <-ctx.Done():
			_, err := stream.CloseAndRecv()
			if err != nil {
				errCh <- fmt.Errorf("[EXECVE] Streaming stopped: %w", err)
				return
			}
			return

		case log, ok := <-logData:
			if !ok {
				_, err = stream.CloseAndRecv()
				if err != nil {
					errCh <- fmt.Errorf("[EXECVE] Log is not ok: %w", err)
					return
				}
				return
			}

			fmt.Println(utils.Info("[INFO] Sending execve log: %w"), log)
			if err = stream.Send(&pb.ExecveLog{
				Pid:           int64(log.Pid),
				Name:          log.Name,
				Comm:          log.Cmd,
				ParentProcess: int64(log.ParentProcess),
				Timestamp:     timestamppb.New(time.Now()),
				AgentId:       agentId,
			}); err != nil {
				errCh <- fmt.Errorf("[EXECVE] Streaming log error: %w", err)
				return
			}
		}
	}
}
