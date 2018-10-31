package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func whiteList(syscalls []string) {
	filter, err := libseccomp.NewFilter(libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		fmt.Printf("Error creating filter: %s\n", err)
	}
	for _, element := range syscalls {
		//fmt.Printf("[+] Whitelisting: %s\n", element)
		syscallID, err := libseccomp.GetSyscallFromName(element)
		if err != nil {
			panic(err)
		}
		filter.AddRule(syscallID, libseccomp.ActAllow)
	}
	filter.Load()
}

func main() {

	var syscalls = []string{"write", "rt_sigaction", "mmap", "clock_gettime", "clone",
		"mprotect", "futex", "openat", "access", "rt_sigprocmask", "fstat", "seccomp",
		"munmap", "wait4", "close", "read", "brk", "set_tid_address", "sigaltstack",
		"prlimit64", "execve", "sched_getaffinity", "set_robust_list", "arch_prctl",
		"gettid", "rt_sigreturn", "getpid", "waitid",
		"readlinkat", "pipe", "pipe2", "exit_group", "connect", "statfs", "socket",
		"lseek", "getgroups", "getgid", "geteuid", "getegid", "getuid", "exit", "fcntl"}

	whiteList(syscalls)

	cmd := exec.Command("/usr/bin/id")
	cmd.SysProcAttr = &syscall.SysProcAttr{
	//Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
	//Unshareflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
}
