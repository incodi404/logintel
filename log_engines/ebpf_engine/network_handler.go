package ebpfengine

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	ebpfhandlers "github.com/incodi404/logintel/ebpf_handlers"
	"github.com/incodi404/logintel/models"
	"github.com/incodi404/logintel/utils"
)

func ISSS_Get_Event_Log(rd *ringbuf.Reader) (models.ISSS_Network_Log_Event_Decoded, error) {
	var decodedLog models.ISSS_Network_Log_Event_Decoded

	netLog, err := ebpfhandlers.EBPF_Reader[models.ISSS_Network_Log_Event](rd)
	if err != nil {
		return models.ISSS_Network_Log_Event_Decoded{}, err
	}

	// decoding log
	decodedLog.Oldstate = models.TCPStates[int(netLog.Oldstate)]
	decodedLog.Newstate = models.TCPStates[int(netLog.Newstate)]
	decodedLog.Family = models.AddressFamilies[int(netLog.Family)]
	decodedLog.Protocol = models.IPProtocols[int(netLog.Protocol)]

	// value as it is
	decodedLog.Sport = netLog.Sport
	decodedLog.Dport = netLog.Dport
	decodedLog.Saddr = utils.FormatIPv4Str(netLog.Saddr)
	decodedLog.Daddr = utils.FormatIPv4Str(netLog.Daddr)

	// PID
	decodedLog.Pid, _ = utils.PidProcessing(int(netLog.Pid))

	return decodedLog, nil
}

func Connect4_Bind4_Get_Event_Log(rd *ringbuf.Reader) (models.Sock_Addr_Event_Decoded, error) {
	var decodedLog models.Sock_Addr_Event_Decoded

	netLog, err := ebpfhandlers.EBPF_Reader[models.Sock_Addr_Event](rd)
	if err != nil {
		return models.Sock_Addr_Event_Decoded{}, err
	}

	decodedLog.User_family = models.UserFamilies[int(netLog.User_family)]
	decodedLog.User_IP4 = utils.UintToIPv4(netLog.User_IP4)
	decodedLog.User_Port = netLog.User_Port
	decodedLog.Family = models.AddressFamilies[int(netLog.Family)]
	decodedLog.Type = models.SocketTypes[int(netLog.Type)]
	decodedLog.Protocol = models.SocketProtocols[int(netLog.Protocol)]
	decodedLog.Uid = netLog.Uid
	decodedLog.Pid, _ = utils.PidProcessing(int(netLog.Pid))

	return decodedLog, nil
}

func Isss_Event() (*ringbuf.Reader, ebpfhandlers.LoadedEBPF, error) {
	var hook_fs = "sock"

	// load
	loaded, err := ebpfhandlers.EBPF_Loader(
		"./././ebpf_build/network_log.o",
		"handle_inet_sock_set_state",
		"tracepoint",
		ebpfhandlers.HookParams{
			Fs:       &hook_fs,
			HookName: "inet_sock_set_state",
		},
	)
	if err != nil {
		return &ringbuf.Reader{}, loaded, err
	}

	// get rd
	rd, err := ebpfhandlers.Ring_Buf_Reader(loaded.Collection)
	if err != nil {
		return &ringbuf.Reader{}, loaded, err
	}

	return rd, loaded, nil
}

func Connect4_Event() (*ringbuf.Reader, ebpfhandlers.LoadedEBPF, error) {
	fs := "/sys/fs/cgroup"

	// loading
	loaded, err := ebpfhandlers.EBPF_Loader(
		"./././ebpf_build/network_log.o",
		"handle_connect4",
		"cgroup",
		ebpfhandlers.HookParams{
			Fs:         &fs,
			HookName:   "connect4",
			AttachType: ebpf.AttachCGroupInet4Connect,
		},
	)
	if err != nil {
		return &ringbuf.Reader{}, loaded, err
	}

	// rd
	rd, err := ebpfhandlers.Ring_Buf_Reader(loaded.Collection)
	if err != nil {
		return &ringbuf.Reader{}, loaded, err
	}

	return rd, loaded, nil
}

func Bind4_Event() (*ringbuf.Reader, ebpfhandlers.LoadedEBPF, error) {
	fs := "/sys/fs/cgroup"

	// loading
	loaded, err := ebpfhandlers.EBPF_Loader(
		"./././ebpf_build/network_log.o",
		"handle_bind4",
		"cgroup",
		ebpfhandlers.HookParams{
			Fs:         &fs,
			HookName:   "bind4",
			AttachType: ebpf.AttachCGroupInet4Bind,
		},
	)
	if err != nil {
		return &ringbuf.Reader{}, loaded, err
	}

	// rd
	rd, err := ebpfhandlers.Ring_Buf_Reader(loaded.Collection)
	if err != nil {
		return &ringbuf.Reader{}, loaded, err
	}

	return rd, loaded, nil
}
