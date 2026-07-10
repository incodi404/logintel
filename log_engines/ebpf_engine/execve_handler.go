package ebpfengine

import (
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	ebpfloader "github.com/incodi404/logintel/ebpf_handlers"
	"github.com/incodi404/logintel/models"
	"github.com/incodi404/logintel/utils"
)

func Execve_Get_Log(rd *ringbuf.Reader) (models.PidInfo, error) {
	execveLog, err := ebpfloader.EBPF_Reader[models.Execve_Log_Event](rd)
	if err != nil {
		fmt.Println(err)
		return models.PidInfo{}, fmt.Errorf(
			"[ERROR] Failed to read execve log: %w", err,
		)
	}

	pid := execveLog.Pid

	// pid processing
	pidInfo, _ := utils.PidProcessing(int(pid))

	return pidInfo, nil
}

func Execve_Log() (*ringbuf.Reader, ebpfloader.LoadedEBPF, error) {
	var hookFs string = "syscalls"

	loaded, err := ebpfloader.EBPF_Loader(
		"./././ebpf_build/execve_log.o",
		"handle_execve",
		"tracepoint",
		ebpfloader.HookParams{
			Fs:       &hookFs,
			HookName: "sys_enter_execve",
		},
	)
	if err != nil {
		fmt.Println(err)
		return &ringbuf.Reader{}, loaded, fmt.Errorf(
			"[ERROR] Failed to load execve_log.o: %w",
			err,
		)
	}

	// defer loaded.Collection.Close()

	rd, err := ebpfloader.Ring_Buf_Reader(loaded.Collection)
	if err != nil {
		fmt.Println(err)
		return &ringbuf.Reader{}, loaded, fmt.Errorf(
			"[ERROR] Failed to get rd in execve hook: %w", err,
		)
	}

	return rd, loaded, nil
}
