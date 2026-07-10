package ebpfhandlers

import (
	// "bytes"
	// "encoding/binary"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	// "github.com/incodi404/logintel/models"
	"github.com/incodi404/logintel/utils"
)

func Ring_Buf_Reader(coll *ebpf.Collection) (*ringbuf.Reader, error) {
	eventMaps := coll.Maps

	// rd of ring buf
	rd, err := ringbuf.NewReader(eventMaps["events"])
	if err != nil {
		return nil, fmt.Errorf(
			utils.Error("[ERROR] Error creating new reader from ring buf: %w"),
			err,
		)
	}

	return rd, nil
}

func EBPF_Reader[T any](rd *ringbuf.Reader) (T, error) {
	var event T // creating event

	// getting data
	record, err := rd.Read()
	if err != nil {
		return event, fmt.Errorf(
			utils.Error("[ERROR] Reading raw data has been failed: %w"),
			err,
		)
	}

	// reinterpreting raw bites without any type safety of Golang
	event = *(*T)(unsafe.Pointer(&record.RawSample[0]))

	if err != nil {
		return event, fmt.Errorf(
			utils.Error("[ERROR] Converting raw data has been failed: %w"),
			err,
		)
	}

	return event, nil
}
