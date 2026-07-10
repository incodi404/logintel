package fileoperations

import (
	"context"

	"github.com/incodi404/logintel/models"
	"golang.org/x/sys/unix"
)

func Fanotify_Log_Collector(
	ctx context.Context,
	fd int,
	rule models.Fanotify_Filter_Rule,
	buf []byte,
	collect chan<- *models.FileOperationLog,
	errCh chan<- error,

) {
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case errCh <- err:
			}

			continue
		}

		var filtered_log *models.FileOperationLog

		// parsing
		/*
			@offset is the address tracking variable here. We are fetching
			each event by this offset.
			event = buf[offset]
			At the initial stage, offset=0 and as we know, all the bytes are 0 after
			initialization. So we are starting from the first event. After processing
			we are the offset value with the Event_len from FanotifyEventMetadata, then
			we will get the address of next event.

			"n" is the total size of bytes that have been occupied by reading
			the events.
		*/
		offset := 0
		for offset < n {
			Event_len, log, err := FanotifyParse(buf, offset)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case errCh <- err:
				}

				continue
			}

			filtered_log, err = Fanotify_Filter(&log, rule)

			offset = offset + Event_len

			select {
			case <-ctx.Done():
				return

			case collect <- filtered_log:
			}
		}
	}
}

func FanotifyLogger() (int, []byte, error) {
	// initializing fanotify instance/file descriptior
	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_CONTENT,
		unix.O_RDONLY,
	)
	if err != nil {
		return 0, []byte{}, err
	}

	// add and remove watcher
	/*
		NOTE:
		unix.FAN_MARK_MOUNT
		This flag changes the target directory from the given directory to whole filesystem.
	*/
	err = unix.FanotifyMark(
		fd,
		unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
		unix.FAN_ACCESS|unix.FAN_MODIFY|unix.FAN_OPEN|unix.FAN_EVENT_ON_CHILD,
		unix.AT_FDCWD,
		"/",
	)
	if err != nil {
		return 0, []byte{}, err
	}

	// reading
	buf := make([]byte, 8192) // 8 KB

	return fd, buf, nil
}
