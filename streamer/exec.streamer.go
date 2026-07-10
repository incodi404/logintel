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

func Exec_Streamer(
	ctx context.Context,
	logData <-chan models.Exec_Log_Event_Decoded,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {

	// generate constructor
	client := pb.NewExecLogUploaderClient(conn)

	agentId := config.ConfigValues.Token.AgentId // config

	// timeout ctx
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// open stream
	stream, err := client.ExecUpload(streamCtx)
	if err != nil {
		errCh <- fmt.Errorf(
			"Opening Exec stream failed: %w", err,
		)
		return
	}

	for {
		select {
		case <-ctx.Done():
			_, err = stream.CloseAndRecv()
			if err != nil {
				errCh <- err
				return
			}

			fmt.Println("[EXEC] Streaming stopped")
			return

		case log, ok := <-logData:
			if !ok {
				_, err = stream.CloseAndRecv()
				if err != nil {
					errCh <- err
					return
				}

				fmt.Println("[EXEC] Streaming stopped")
				return
			}

			fmt.Println(utils.Info("[INFO] Sending exec log: %w"), log)
			if err = stream.Send(&pb.ExecLog{
				Filename:  log.Filename,
				Pid:       log.Pid,
				OldPid:    log.OldPid,
				Uid:       log.Uid,
				Comm:      log.Comm,
				Timestamp: timestamppb.New(time.Now()),
				AgentId:   agentId,
			}); err != nil {
				errCh <- fmt.Errorf(
					"Exec log streaming error: %w", err,
				)

				return
			}
		}
	}
}
