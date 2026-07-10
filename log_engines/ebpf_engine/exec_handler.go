package ebpfengine

import (
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	ebpfhandlers "github.com/incodi404/logintel/ebpf_handlers"
	"github.com/incodi404/logintel/models"
	"github.com/incodi404/logintel/utils"
)

func Exec_Get_Log(rd *ringbuf.Reader) (models.Exec_Log_Event_Decoded, error) {
	var decodedLog models.Exec_Log_Event_Decoded

	execveLog, err := ebpfhandlers.EBPF_Reader[models.Exec_Log_Event](rd)
	if err != nil {
		fmt.Println(err)
		return models.Exec_Log_Event_Decoded{}, fmt.Errorf(
			"[ERROR] Failed to read exec log: %w", err,
		)
	}

	decodedLog.Filename = utils.ByteToStrFilename(execveLog.Filename)
	decodedLog.Comm = utils.ByteToStrComm(execveLog.Comm)
	decodedLog.Pid = execveLog.Pid
	decodedLog.OldPid = execveLog.OldPid
	decodedLog.Uid = execveLog.Uid

	return decodedLog, nil
}

func Exec_Handler() (*ringbuf.Reader, ebpfhandlers.LoadedEBPF, error) {
	hookFs := "sched"

	// load
	loaded, err := ebpfhandlers.EBPF_Loader(
		"./././ebpf_build/exec_log.o",
		"handle_exec",
		"tracepoint",
		ebpfhandlers.HookParams{
			Fs:       &hookFs,
			HookName: "sched_process_exec",
		},
	)
	if err != nil {
		return &ringbuf.Reader{}, loaded, fmt.Errorf(
			"[ERROR] Failed to load exec_log.o: %w", err,
		)
	}

	// defer loaded.Collection.Close()

	// rd
	rd, err := ebpfhandlers.Ring_Buf_Reader(loaded.Collection)
	if err != nil {
		return &ringbuf.Reader{}, loaded, fmt.Errorf(
			"[ERROR] Failed to get rd of exec hook: %w", err,
		)
	}

	return rd, loaded, nil
}
