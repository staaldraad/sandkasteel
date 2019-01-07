package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func whiteList(syscalls []string) (*libseccomp.ScmpFilter, error) {
	filter, err := libseccomp.NewFilter(libseccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		fmt.Printf("Error creating filter: %s\n", err)
	}
	for _, element := range syscalls {
		syscallID, err := libseccomp.GetSyscallFromName(element)
		if err != nil {
			return nil, err
		}
		err = filter.AddRule(syscallID, libseccomp.ActAllow)
		if err != nil {
			return nil, err
		}
	}
	err = filter.Load()
	return filter, err
}

func mergeList(filter *libseccomp.ScmpFilter, syscalls []string) (*libseccomp.ScmpFilter, error) {

	for _, element := range syscalls {
		syscallID, err := libseccomp.GetSyscallFromName(element)
		if err != nil {
			return nil, err
		}
		err = filter.AddRule(syscallID, libseccomp.ActAllow)
		if err != nil {
			return nil, err
		}
	}
	err := filter.Load()
	return filter, err
}

func trace(pid int) error {
	/*
	   Core code for trace taken from github.com/lizrice/strace-from-scratch
	*/

	var regs syscall.PtraceRegs
	var ss syscallCounter

	ss = ss.init()

	exit := true
	var err error
	for {
		if exit {
			err = syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				break
			}
			ss.inc(regs.Orig_rax)
		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			return err
		}

		_, err = syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			return err
		}

		exit = !exit
	}
	fmt.Println("\n---Syscalls for child (save to file and load with -seccomp filename): ")
	ss.printCalls()
	return nil
}

func readLines(path string) ([]string, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	return lines, nil
}

func main() {

	tracePtr := flag.Bool("trace", false, "Trace and print child process syscalls")
	seccompFilePtr := flag.String("seccomp", "", "File with list of syscalls to whitelist for child proccess")
	flag.Parse()

	var sandkasteel_syscalls = []string{
		"read",
		"write",
		"open",
		"close",
		"fstat",
		"lseek",
		"mmap",
		"mprotect",
		"munmap",
		"brk",
		"rt_sigaction",
		"rt_sigprocmask",
		"rt_sigreturn",
		"clone",
		"execve",
		"wait4",
		"fcntl",
		"arch_prctl",
		"futex",
		"sched_getaffinity",
		"set_tid_address",
		"waitid",
		"openat",
		"readlinkat",
		"pselect6",
		"set_robust_list",
		"pipe2",
		"seccomp",
		"exit_group",
		"exit",
	}

	var child_syscalls = []string{}

	if *seccompFilePtr != "" {
		var err error
		child_syscalls, err = readLines(*seccompFilePtr)

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

	}

	syscalls := append(sandkasteel_syscalls, child_syscalls...)

	// if not tracing, implement seccomp filter
	if !*tracePtr {
		whiteList(syscalls)
	}

	//trace()
	var prog string
	var args []string

	if len(flag.Args()) == 0 {
		fmt.Println("Need at least 1 argument")
		os.Exit(1)
	}

	prog = flag.Args()[0]

	if len(flag.Args()) > 1 {
		args = flag.Args()[1:]
	}

	cmd := exec.Command(prog, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
	//Cloneflags: syscall.CLONE_NEWUSER, //syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
	//Unshareflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
	//UidMappings: []syscall.SysProcIDMap{
	//	{ContainerID: 65534, HostID: 65534, Size: 1},
	//},
	}

	if !*tracePtr {
		cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWUSER
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: 65534, HostID: 65534, Size: 1},
		}
	} else {
		//ss = ss.init()
		cmd.SysProcAttr.Ptrace = true
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if !*tracePtr {
		if err := cmd.Run(); err != nil {
			fmt.Println("ERROR", err)
			os.Exit(1)
		}
	} else {
		cmd.Start()
		err := cmd.Wait()
		if err != nil {
			fmt.Printf("Wait returned: %v\n", err)
		}

		pid := cmd.Process.Pid

		trace(pid)
	}
}
