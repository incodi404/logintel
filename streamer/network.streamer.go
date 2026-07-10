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

func ISSS_Streamer(
	ctx context.Context,
	collect <-chan models.ISSS_Network_Log_Event_Decoded,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {
	// constructor
	client := pb.NewNetworkLogUploaderClient(conn)

	// stream ctx
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	agentId := config.ConfigValues.Token.AgentId // config

	// opening stream
	stream, err := client.ISSSUpload(streamCtx)
	if err != nil {
		errCh <- fmt.Errorf("[ISSS] Error opening stream: %w", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			_, err := stream.CloseAndRecv()
			if err != nil {
				errCh <- fmt.Errorf("[ISSS] Error closing stream: %w", err)
				return
			}
			return

		case log, ok := <-collect:
			if !ok {
				_, err := stream.CloseAndRecv()
				if err != nil {
					errCh <- fmt.Errorf("[ISSS] Error closing stream: %w", err)
					return
				}
				errCh <- fmt.Errorf("[ISSS] Log is not ok")
				return
			}

			fmt.Println(utils.Info("[ISSS] Log received: "), log)
			uploadLog := &pb.ISSSLog{
				OldState:      log.Oldstate,
				NewState:      log.Newstate,
				SPort:         uint32(log.Sport),
				DPort:         uint32(log.Dport),
				Family:        log.Family,
				Protocol:      log.Protocol,
				SAddr:         log.Saddr,
				DAddr:         log.Daddr,
				Pid:           int64(log.Pid.Pid),
				Name:          log.Pid.Name,
				Comm:          log.Pid.Cmd,
				ParentProcess: int64(log.Pid.ParentProcess),
				Timestamp:     timestamppb.New(time.Now()),
				AgentId:       agentId,
			}
			if err = stream.Send(uploadLog); err != nil {
				errCh <- fmt.Errorf("[ISSS] Streaming log error: %w", err)
				return
			}

		}
	}
}

func Connect4_Streamer(
	ctx context.Context,
	collect <-chan models.Sock_Addr_Event_Decoded,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {
	// constructor
	client := pb.NewNetworkLogUploaderClient(conn)

	// stream ctx
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	agentId := config.ConfigValues.Token.AgentId // config

	// opening stream
	stream, err := client.Connect4Upload(streamCtx)
	if err != nil {
		errCh <- fmt.Errorf("[CONNECT4] Error opening stream: %w", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			_, err := stream.CloseAndRecv()
			if err != nil {
				errCh <- fmt.Errorf("[CONNECT4] Error closing stream: %w", err)
				return
			}
			return

		case log, ok := <-collect:
			if !ok {
				_, err := stream.CloseAndRecv()
				if err != nil {
					errCh <- fmt.Errorf("[CONNECT4] Error closing stream: %w", err)
					return
				}
				errCh <- fmt.Errorf("[CONNECT4] Log is not ok")
				return
			}

			fmt.Println(utils.Info("[CONNECT4] Log received: "), log)
			uploadLog := &pb.Connect4Log{
				Timestamp:     timestamppb.New(time.Now()),
				UserFamily:    log.User_family,
				UserIPv4:      log.User_IP4,
				UserPort:      log.User_Port,
				Family:        log.Family,
				Type:          log.Type,
				Protocol:      log.Protocol,
				Uid:           log.Uid,
				Pid:           int64(log.Pid.Pid),
				Name:          log.Pid.Name,
				Comm:          log.Pid.Cmd,
				ParentProcess: int64(log.Pid.ParentProcess),
				AgentId:       agentId,
			}
			if err = stream.Send(uploadLog); err != nil {
				errCh <- fmt.Errorf("[CONNECT4] Streaming log error: %w", err)
				return
			}
		}
	}
}

func Bind4_Streamer(
	ctx context.Context,
	collect <-chan models.Sock_Addr_Event_Decoded,
	errCh chan<- error,
	conn *grpc.ClientConn,
) {
	// constructor
	client := pb.NewNetworkLogUploaderClient(conn)

	// stream ctx
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	agentId := config.ConfigValues.Token.AgentId // config

	// opening stream
	stream, err := client.Bind4Upload(streamCtx)
	if err != nil {
		errCh <- fmt.Errorf("[BIND4] Error opening stream: %w", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			_, err := stream.CloseAndRecv()
			if err != nil {
				errCh <- fmt.Errorf("[BIND4] Error closing stream: %w", err)
				return
			}
			return

		case log, ok := <-collect:
			if !ok {
				_, err := stream.CloseAndRecv()
				if err != nil {
					errCh <- fmt.Errorf("[BIND4] Error closing stream: %w", err)
					return
				}
				errCh <- fmt.Errorf("[BIND4] Log is not ok")
				return
			}

			fmt.Println(utils.Info("[BIND4] Log received: "), log)
			uploadLog := &pb.Bind4Log{
				Timestamp:     timestamppb.New(time.Now()),
				UserFamily:    log.User_family,
				UserIPv4:      log.User_IP4,
				UserPort:      log.User_Port,
				Family:        log.Family,
				Type:          log.Type,
				Protocol:      log.Protocol,
				Uid:           log.Uid,
				Pid:           int64(log.Pid.Pid),
				Name:          log.Pid.Name,
				Comm:          log.Pid.Cmd,
				ParentProcess: int64(log.Pid.ParentProcess),
				AgentId:       agentId,
			}
			if err = stream.Send(uploadLog); err != nil {
				errCh <- fmt.Errorf("[BIND4] Streaming log error: %w", err)
				return
			}
		}
	}
}
