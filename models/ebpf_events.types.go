package models

// tracepoint/syscalls/sys_enter_execve
type Execve_Log_Event struct {
	Pid uint32
}

// tracepoint/sched/sched_process_exec
type Exec_Log_Event struct {
	Filename [64]byte
	Pid      uint32
	OldPid   uint32
	Uid      uint32
	Comm     [16]byte
}

type Exec_Log_Event_Decoded struct {
	Filename string
	Pid      uint32
	OldPid   uint32
	Uid      uint32
	Comm     string
}

// tracepoint/sock/inet_sock_set_state
type ISSS_Network_Log_Event struct {
	Skaddr   uint64 // largest byte
	Oldstate int32
	Newstate int32
	Sport    uint16
	Dport    uint16
	Family   uint16
	Protocol uint16
	Saddr    [4]byte
	Daddr    [4]byte
	Saddr_v6 [16]byte
	Daddr_v6 [16]byte
	Pid      uint32

	Pad uint32 // padding to make alignment
}

// Fully decoded and described
type ISSS_Network_Log_Event_Decoded struct {
	Oldstate string
	Newstate string
	Sport    uint16
	Dport    uint16
	Family   string
	Protocol string
	Saddr    string
	Daddr    string
	Pid      PidInfo
}

// connect4 & bind4
type Sock_Addr_Event struct {
	User_family uint32
	User_IP4    uint32
	User_Port   uint32
	Family      uint32
	Type        uint32
	Protocol    uint32
	Pid         uint32
	Uid         uint32
}

// Fully decoded and described
type Sock_Addr_Event_Decoded struct {
	User_family string
	User_IP4    string
	User_Port   uint32
	Family      string
	Type        string
	Protocol    string
	Pid         PidInfo
	Uid         uint32
}
