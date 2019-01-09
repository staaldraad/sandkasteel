# Sandkasteel

A small go wrapper to call a process in a new namespace, with a new UID, GID and seccomp.

The seccomp list will need to be adjusted according to the child binary's requirements. You need to supply the full path for the child binary as well, since there is no PATH.

## Example:

First you'll need to know the syscalls that the child process requires. To do this run with the `-trace` option:

```
./sandkasteel -trace /usr/bin/id 
Wait returned: stop signal: trace/breakpoint trap
uid=1000(staaldraad) gid=1000(staaldraad) groups=1000(staaldraad)

---Syscalls for child (save to file and load with -seccomp filename):
read
write
open
close
fstat
lseek
mmap
mprotect
munmap
brk
rt_sigaction
rt_sigprocmask
access
socket
connect
execve
getrlimit
getuid
getgid
geteuid
getegid
getgroups
statfs
arch_prctl
set_tid_address
set_robust_list
```
Save the output into a file and supply this when calling the child process. This example assumes uers-namespaces is enabled, otherwise run with `sudo`/root-user.

```
./sandkasteel -seccomp sample_id_syscalls.txt /usr/bin/id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
``` 
If you don't have permission to, or don't want to, run in a new usernamespace (or new UID/GID), supply the `-nons` flag:

```
./sandkasteel -nons -seccomp sample_id_seccomp.txt /usr/bin/id
uid=1000(staaldraad) gid=1000(staaldraad) groups=1000(staaldraad)
```

# Credits
The syscall tracing code was taken from [https://github.com/lizrice/strace-from-scratch](https://github.com/lizrice/strace-from-scratch)

More info in her blogpost here; [https://hackernoon.com/strace-in-60-lines-of-go-b4b76e3ecd64](https://hackernoon.com/strace-in-60-lines-of-go-b4b76e3ecd64)
