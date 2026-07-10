package utils

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	models "github.com/incodi404/logintel/models"
)

func PidProcessing(pid int) (models.PidInfo, error) {
	// process name
	name, err := getProcessName(pid)
	if err != nil {
		return models.PidInfo{}, err
	}

	// cmd
	cmd, err := getCommand(pid)
	if err != nil {
		return models.PidInfo{}, err
	}

	// parent process
	parentProc, err := getParentProcess(pid)
	if err != nil {
		return models.PidInfo{}, err
	}

	return models.PidInfo{
		Pid:           pid,
		Name:          string(name),
		Cmd:           string(cmd),
		ParentProcess: parentProc,
	}, nil
}

func getProcessName(pid int) (string, error) {
	name, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown", err
	} else {
		return strings.TrimSpace(string(name)), nil
	}
}

func getCommand(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "unknown", err
	} else {
		return strings.ReplaceAll(string(data), "\x00", " "), nil
	}
}

func getParentProcess(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data)) // splitting everything based on " "

	// out of bound handliing
	if len(fields) < 4 {
		return 0, err
	}

	ppid, _ := strconv.Atoi(fields[3]) // string => int (ASCII => Integer)

	return ppid, nil
}
