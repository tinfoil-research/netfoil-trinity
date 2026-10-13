package seccomp

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func SetNoNewPrivs() error {
	_, _, errInt := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, uintptr(1), 0, 0, 0, 0)
	if errInt != 0 {
		return fmt.Errorf("error setting NoNewPrivs: %s\n", errInt)
	}

	return nil
}

type ArgumentFilters struct {
	SocketIPv4TCPUDP bool
}

func ApplyFilter(allowedSyscalls []uint32, argumentFilters ArgumentFilters) error {
	instructions := make([]bpf.Instruction, 0)

	defaultSyscalls := []uint32{
		// @default
		unix.SYS_RT_SIGRETURN,
		unix.SYS_SCHED_GETAFFINITY,
		unix.SYS_SCHED_YIELD,
		unix.SYS_FUTEX,
		unix.SYS_GETPID,
		unix.SYS_GETRANDOM,
		unix.SYS_GETTID,
		unix.SYS_MUNMAP,
		unix.SYS_NANOSLEEP,
		unix.SYS_EXIT,
		unix.SYS_EXIT_GROUP,
		// Needed when vDSO is disabled,
		unix.SYS_CLOCK_GETTIME,

		// @basic-io
		unix.SYS_CLOSE,
		unix.SYS_READ,
		unix.SYS_WRITE,
		unix.SYS_PREAD64,

		// @signal
		unix.SYS_RT_SIGPROCMASK,
		unix.SYS_RT_SIGACTION,
		unix.SYS_SIGALTSTACK,

		// @io-event
		unix.SYS_EPOLL_CTL,
		unix.SYS_EPOLL_PWAIT,

		// @process
		unix.SYS_TGKILL,

		// @system-service
		unix.SYS_MADVISE,
	}

	allowedSyscalls = append(allowedSyscalls, defaultSyscalls...)

	syscallOffset := uint32(0)
	archOffset := uint32(4)
	intSize := 4

	argOffset0 := uint32(16)
	argOffset1 := uint32(24)
	argOffset2 := uint32(32)
	argOffset3 := uint32(40)

	instructions = append(instructions, bpf.LoadAbsolute{Off: archOffset, Size: intSize})
	instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.AUDIT_ARCH_X86_64, SkipTrue: 1})
	instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_KILL_PROCESS)})

	instructions = append(instructions, bpf.LoadAbsolute{Off: syscallOffset, Size: intSize})
	for _, s := range allowedSyscalls {
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: s, SkipTrue: 1})
		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_ALLOW)})
	}

	// mmap
	// prctl PR_SET_MDWE is an alternative
	{
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.SYS_MMAP, SkipTrue: 9})

		instructions = append(instructions, bpf.LoadAbsolute{Off: argOffset2, Size: intSize})
		instructions = append(instructions, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: unix.PROT_EXEC})

		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.PROT_EXEC, SkipTrue: 1})
		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_KILL_PROCESS)})

		instructions = append(instructions, bpf.LoadAbsolute{Off: argOffset3, Size: intSize})
		instructions = append(instructions, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: unix.MAP_SHARED | unix.MAP_PRIVATE | unix.MAP_ANON})

		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.MAP_PRIVATE | unix.MAP_ANON, SkipTrue: 1})
		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_KILL_PROCESS)})

		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_ALLOW)})
	}

	// clone
	{
		instructions = append(instructions, bpf.LoadAbsolute{Off: syscallOffset, Size: intSize})
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.SYS_CLONE, SkipTrue: 4})

		instructions = append(instructions, bpf.LoadAbsolute{Off: argOffset0, Size: intSize})

		cloneFlags := uint32(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_SYSVSEM | unix.CLONE_THREAD | unix.CLONE_SETTLS)
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpEqual, Val: cloneFlags, SkipTrue: 1})
		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_KILL_PROCESS)})
		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_ALLOW)})
	}

	if argumentFilters.SocketIPv4TCPUDP {
		instructions = append(instructions, bpf.LoadAbsolute{Off: syscallOffset, Size: intSize})
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.SYS_SOCKET, SkipTrue: 14})

		instructions = append(instructions, bpf.LoadAbsolute{Off: argOffset0, Size: intSize})
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.AF_INET, SkipTrue: 1})
		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_KILL_PROCESS)})

		instructions = append(instructions, bpf.LoadAbsolute{Off: argOffset1, Size: intSize})
		socketMask := uint32(0xf)
		instructions = append(instructions, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: socketMask})

		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SOCK_DGRAM, SkipTrue: 2})
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SOCK_STREAM, SkipTrue: 1})
		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_KILL_PROCESS)})

		instructions = append(instructions, bpf.LoadAbsolute{Off: argOffset2, Size: intSize})
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_UDP, SkipTrue: 3})
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_TCP, SkipTrue: 2})
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1})
		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_KILL_PROCESS)})

		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_ALLOW)})
	}

	instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_KILL_PROCESS)})

	program, err := createSeccompProgram(instructions)
	if err != nil {
		return err
	}

	_, _, errInt := syscall.AllThreadsSyscall6(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(program)), 0, 0, 0)
	if errInt != 0 {
		return fmt.Errorf("error setting seccomp: %d", errInt)
	}

	return nil
}

func createSeccompProgram(instructions []bpf.Instruction) (*syscall.SockFprog, error) {
	rawInstructions, err := bpf.Assemble(instructions)
	if err != nil {
		return nil, err
	}

	filter := make([]syscall.SockFilter, 0)
	for _, instruction := range rawInstructions {
		filter = append(filter, syscall.SockFilter{
			Code: instruction.Op,
			Jt:   instruction.Jt,
			Jf:   instruction.Jf,
			K:    instruction.K,
		})
	}

	program := &syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	return program, nil
}
