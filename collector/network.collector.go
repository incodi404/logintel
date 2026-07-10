package collector

import (
	"context"

	ebpfengine "github.com/incodi404/logintel/log_engines/ebpf_engine"
	"github.com/incodi404/logintel/models"
)

func ISS_Log_Collector(
	ctx context.Context,
	collect chan<- models.ISSS_Network_Log_Event_Decoded,
	errCh chan<- error,
) {
	rd, loaded, err := ebpfengine.Isss_Event()
	if err != nil {
		errCh <- err
		return
	}
	defer loaded.Link.Close()
	defer loaded.Collection.Close()
	defer rd.Close()

	for {
		log, err := ebpfengine.ISSS_Get_Event_Log(rd)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case errCh <- err:
			}

			continue
		}

		select {
		case <-ctx.Done():
			return

		case collect <- log:
		}
	}
}

func Connect4_Log_Collector(
	ctx context.Context,
	collect chan<- models.Sock_Addr_Event_Decoded,
	errCh chan<- error,
) {
	rd, loaded, err := ebpfengine.Connect4_Event()
	if err != nil {
		errCh <- err
		return
	}
	defer loaded.Link.Close()
	defer loaded.Collection.Close()
	defer rd.Close()

	for {
		log, err := ebpfengine.Connect4_Bind4_Get_Event_Log(rd)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case errCh <- err:
			}

			continue
		}

		select {
		case <-ctx.Done():
			return

		case collect <- log:
		}
	}
}

func Bind4_Log_Collector(
	ctx context.Context,
	collect chan<- models.Sock_Addr_Event_Decoded,
	errCh chan<- error,
) {
	rd, loaded, err := ebpfengine.Bind4_Event()
	if err != nil {
		errCh <- err
		return
	}
	defer loaded.Link.Close()
	defer loaded.Collection.Close()
	defer rd.Close()

	for {
		log, err := ebpfengine.Connect4_Bind4_Get_Event_Log(rd)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case errCh <- err:
			}

			continue
		}

		select {
		case <-ctx.Done():
			return

		case collect <- log:
		}
	}
}
