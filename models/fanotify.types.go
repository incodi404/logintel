package models

type PidInfo struct {
	Pid           int
	Name          string
	Cmd           string
	ParentProcess int
}

type FileOperationLog struct {
	Path   string
	Events []string
	Pid    PidInfo
}
