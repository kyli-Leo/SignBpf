# SignBpf: an ebpf program base on libbpf-bootstrap that checks signature and limit resources of unsigned executable

## General Inforamtion
SignBpf aims to work as a white-list version of chroot. Instead of limiting the software to a new directory, we allow users to limit certain directories that they do not want the uncertified program to access. SignBpf would reject the access of those directories in system calls. However, keep in mind that we only block the file access and other access are still possible. This is not a virtual sandbox.

## Install Dependencies
The program requires you to have the dependencies to run libbpf and lsm

### Basic Dependnecies

You will need `clang` (at least v11 or later), `libelf` and `zlib` to build
our program.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```
On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```
We recommend running the program on Ubuntu as that's what we used in development.

You need `bpftool` to build the source code
Go to bpftool folder and run `make install`

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
$ sudo ./lsm ./sampleSignature.txt  sampleSignature.txt testChecksum.txt ./test.sh
checksum file read: Success
The sha256 checksum does not match
Now executing the software with limit
cat: ./sampleSignature.txt: Operation not permitted
^C
```


# Troubleshooting
In case that editting `GRUB_CMDLINE_LINUX` does not work, try the following (... means the original settings, please don't mess that up)

```
GRUB_CMDLINE_LINUX_DEFAULT=" ... lsm=bpf"
GRUB_CMDLINE_LINUX="lsm= ...bpf"
```
