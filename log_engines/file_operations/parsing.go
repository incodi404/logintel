package fileoperations

import (
	"fmt"
	"os"
	"unsafe"

	models "github.com/incodi404/logintel/models"
	"github.com/incodi404/logintel/utils"
	"golang.org/x/sys/unix"
)

func FanotifyParse(buf []byte, offset int) (Event_len int, log models.FileOperationLog, err error) {

	if offset+int(unsafe.Sizeof(unix.FanotifyEventMetadata{})) > len(buf) {
		return 0, models.FileOperationLog{}, fmt.Errorf("Buf is too small")
	}

	// copy the raw bytes to FanotifyEventMetadata
	metadata := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))

	// verifying Fd
	if int(metadata.Fd) < 0 {
		return 0, models.FileOperationLog{}, fmt.Errorf("Fd is less than 0")
	}

	// fmt.Println(metadata.Fd)
	standardLog := convertToStandardLog(metadata)

	// closing fd :: not using defer() to avoid storing the close function in stack
	if int(metadata.Fd) >= 0 {
		unix.Close(int(metadata.Fd))
	}

	return int(metadata.Event_len), standardLog, err
}

func convertToStandardLog(metadata *unix.FanotifyEventMetadata) models.FileOperationLog {
	// finding path
	path, err := findPathByFd(int(metadata.Fd))
	if err != nil {
		fmt.Println(utils.Error("[ERROR] Error fetching path from fd :: "), err)
	}

	// events
	events := fetchEvents(int(metadata.Mask))

	// pid details
	procInfo, _ := utils.PidProcessing(int(metadata.Pid))

	return models.FileOperationLog{
		Path:   path,
		Events: events,
		Pid:    procInfo,
	}
}

func findPathByFd(fd int) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", int(fd)))
	if err != nil {
		return "", err
	} else {
		return path, nil
	}
}

func fetchEvents(mask int) []string {
	var events []string // events will be stored as string for readable format

	// events
	if mask&unix.FAN_ACCESS != 0 {
		events = append(events, "ACCESSED")
	}

	if mask&unix.FAN_MODIFY != 0 {
		events = append(events, "MODIFIED")
	}

	if mask&unix.FAN_OPEN != 0 {
		events = append(events, "OPENED")
	}

	return events
}
