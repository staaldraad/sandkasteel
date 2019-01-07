# Sandkasteel

A small go wrapper to call a process in a new namespace, with a new UID, GID and seccomp.

The seccomp list will need to be adjusted according to the child binary's requirements. You need to supply the full path for the child binary as well, since there is no PATH.

## Example:

This assumes uers-namespaces is enabled, otherwise run with `sudo`/root-user.

```
./sandkasteel /usr/bin/id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
``` 

