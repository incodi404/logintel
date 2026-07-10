package ebpfhandlers

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/incodi404/logintel/utils"
)

type HookParams struct {
	Fs         *string // pointer because it can be 'nil'
	HookName   string
	AttachType ebpf.AttachType
}

type LoadedEBPF struct {
	Collection *ebpf.Collection
	Link       link.Link
}

func EBPF_Loader(objFile string, progName string, hookType string, hookParams HookParams) (LoadedEBPF, error) {
	// remove memlock
	err := rlimit.RemoveMemlock()
	if err != nil {
		return LoadedEBPF{}, fmt.Errorf(
			utils.Error("[ERROR] RemoveMemlock has been failed to remove memlock: %w"),
			err,
		)
	}

	// loading compiled object file
	spec, err := ebpf.LoadCollectionSpec(objFile)
	if err != nil {
		return LoadedEBPF{}, fmt.Errorf(
			utils.Error("[ERROR] Loading .o file has been failed: %w"),
			err,
		)
	}

	// fmt.Println("Spec: ", spec)

	// loading all program to kernel and getting the collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return LoadedEBPF{}, fmt.Errorf(
			utils.Error("[ERROR] Loading .o file to kernel and getting collection has been failed: %w"),
			err,
		)
	}

	// fmt.Println("Coll: ", coll)

	prog := coll.Programs[progName]
	if prog == nil {
		return LoadedEBPF{}, fmt.Errorf(
			utils.Error("[ERROR] Given program not found in collection: %w"),
			err,
		)
	}

	// fmt.Println("Prog: ", prog)

	var hookRes link.Link

	if hookParams.HookName == "" {
		return LoadedEBPF{}, fmt.Errorf(
			utils.Error("[ERROR] Hook name is required"),
		)
	}

	// dynamic hook type
	switch hookType {

	case "tracepoint":
		fs := hookParams.Fs

		// check fs
		if fs == nil || *fs == "" {
			return LoadedEBPF{}, fmt.Errorf(
				utils.Error("[ERROR] Fs is required for tracepoint hook"),
			)
		}

		tracep, err := link.Tracepoint(
			*fs,
			hookParams.HookName,
			prog,
			nil,
		)
		if err != nil {
			return LoadedEBPF{}, fmt.Errorf(
				utils.Error("[ERROR] Attaching tracepoint has been failed: %w"),
				err,
			)
		}

		hookRes = tracep

	case "kprobe":
		kpro, err := link.Kprobe(
			hookParams.HookName,
			prog,
			nil,
		)
		if err != nil {
			return LoadedEBPF{}, fmt.Errorf(
				utils.Error("[ERROR] Attaching kprobe has been failed: %w"),
				err,
			)
		}

		hookRes = kpro

	case "cgroup":
		cgroup, err := link.AttachCgroup(link.CgroupOptions{
			Path:    *hookParams.Fs,
			Program: prog,
			Attach:  hookParams.AttachType,
		})
		if err != nil {
			return LoadedEBPF{}, fmt.Errorf(
				utils.Error("[ERROR] Attaching cgroup has been failed: %w"),
				err,
			)
		}

		hookRes = cgroup

	default:
		return LoadedEBPF{}, fmt.Errorf(
			utils.Error("[ERROR] Invalid hook type"),
		)

	}

	return LoadedEBPF{
		Collection: coll,
		Link:       hookRes,
	}, nil
}
