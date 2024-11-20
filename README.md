 # SignBpf base on libbpf-bootstrap: a bpf program that checks signature and limit resources of unsigned executable
## Install Dependencies

### Basic Dependnecies

You will need `clang` (at least v11 or later), `libelf` and `zlib` to build
our program

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```
### LSM availability
Your linux keneral version needs to be higher than 5.7 to have LSM.
You would need to check that if your kernel enables LSM to ensure the correct functionality of the program.

``` shell
$ cat /boot/config-$(uname -r) | grep BPF_LSM
CONFIG_BPF_LSM=y
```

If the output is correct, check if BPF is enabled in lsm output.

``` shell
$ cat /sys/kernel/security/lsm
ndlock,lockdown,yama,integrity,apparmor,bpf
```

If the output does not have bpf, edit `/etc/default/grub`:
```
GRUB_CMDLINE_LINUX="lsm=ndlock,lockdown,yama,integrity,apparmor,bpf"
```
Then update the grub configuration and restart the system (Check again to make sure you reach the requirement).

## How to Compile and Run

Makefile build:

```
$ cd source
$ make
$ sudo ./lsm (with additional argument)
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
00:21:22 EXIT  python3.8        4032353 4032352 [0] (123ms)
00:21:22 EXEC  mkdir            4032379 4032337 /usr/bin/mkdir
00:21:22 EXIT  mkdir            4032379 4032337 [0] (1ms)
00:21:22 EXEC  basename         4032382 4032381 /usr/bin/basename
00:21:22 EXIT  basename         4032382 4032381 [0] (0ms)
00:21:22 EXEC  sh               4032381 4032380 /bin/sh
00:21:22 EXEC  dirname          4032384 4032381 /usr/bin/dirname
00:21:22 EXIT  dirname          4032384 4032381 [0] (1ms)
00:21:22 EXEC  readlink         4032387 4032386 /usr/bin/readlink
^C
```


# Troubleshooting
In case that editting `GRUB_CMDLINE_LINUX` does not work, try the following (... means the original settings, please don't mess that up)

```
GRUB_CMDLINE_LINUX_DEFAULT=" ... lsm=bpf"
GRUB_CMDLINE_LINUX="lsm= ...bpf"
```
