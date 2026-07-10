package collector

import (
	"context"

	ebpfengine "github.com/incodi404/logintel/log_engines/ebpf_engine"
	"github.com/incodi404/logintel/models"
)

func Execve_Log_Collector(
	ctx context.Context,
	collect chan<- models.PidInfo,
	errCh chan<- error,
) {
	rd, loaded, err := ebpfengine.Execve_Log()
	if err != nil {
		errCh <- err
		return
	}
	defer loaded.Link.Close()
	defer loaded.Collection.Close()
	defer rd.Close()

	for {
		log, err := ebpfengine.Execve_Get_Log(rd)
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
