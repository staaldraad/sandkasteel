package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func main() {
    cmd := exec.Command("id")
	cmd.SysProcAttr = &syscall.SysProcAttr{
				Cloneflags:   syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
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
