
# LINUX

```shell


# process & memory (arch_mem)
   process, hardware interrupt (timer) -> kernel -> process -> hardware interrupt(timer)..., threads, scheduling, pcb
   memory, kernel space, user space, virtual address (page num + distance), physical address, page table, page, frame, mmu, tlb, major fault, minor fault
   ps, top, lsof, strace, ltrace, renice, uptime, trace-cmd, kernelshark
   vmstat, iostat, iotop, pidstat
   cgroup, /proc/self/cgroup, /sys/fs/cgroup

# device (driver)
   rootfs, /bin, /dev, /etc, /home, /lib, /proc, /run, /sys, /sbin, /tmp, /usr, /var, /boot, /media, /opt
   /dev, block, character, pipe, socket, user i/o oriented, /sys/devices, actual device info
     udev, devtmpfs, kernel sends uevent to udev, udev initializes and registers devices, in devtmpfs when booting
     udevadm info --query=all --name=/dev/sda, udevadm monitor
     kernel block device interface < - > scsi device driver < - > bus < - > (ATA, USB...) bridge driver < - > device
   disk, partition table -> partition -> fs data structure -> fs (maybe rootfs) data
     parted -l, fdisk /dev/sdd, mkfs -t ext4 /dev/sdf2, mount -t ext4 /dev/sdf2 /home/some, umount /home/some, blkid, /etc/fstab
     lvm, pvs, pvdisaply, vgs, vgdisplay, lvs, lvdisplay, pvcreate,vgcreate, vgextend, lvcreate, lvextend
     block device (kernel) > devmapper (kernel) > lvm (user)
     inode (data pointer), block bitmap (allocation pointer), fsck > inode != block bitmap > lost + found
   network, physical, internet, transport, application, ipv4, ipv6
     ping, host, ip, iw, linux network interface
     netplan, /etc/netplan, networkmanager, /etc/NetworkManager
     /etc/hosts, /etc/resolv.conf, /etc/nsswitch.conf
     netstat, tcp, udp
     iptables
     user process < - > kernel socket (system call) < - > network
     ipc (inter process communication) > unix domain socket > eg) mysql.sock
     rsync
# syscall & user mode (os)
  shell
  vim
  build-essential
  go
  rust
  make
  git
  curl
  podman
  virsh
  wireshark
  libreoffice
  chrome
  vscode

harware (interrupt)

kernel vas

  interrupt (hard, soft irq)

  process 

process vas

  user (syscall)


```


```shell

# process & memory

# procfs : /proc/*

# kernel stacks

cat /proc/$PID/stack

# user stacks

gdb

# both

# use eBPF

sudo stackcount-bpfcc -p $PID -v -d

# device

# sysfs: /sys/*

```

```shell

# network protocol

# l2 link

(ethernet)
preamble
src
dst
type/len
data (payload)

switch > mac address table > flooding, filtering and forwarding, ageing

# l3 network

(ipv4)
version
headlen
servicetype
packetlen
identifier
flagmentation offset
ttl
proto
header csum
src 
dst
option
padding
data(payload)
-
(ipv6)
version
traffic class
flow label
payload len
next header
hop limitation
src
dst
data(payload)
-
(arp)
hardware type
proto type
hardware addrlen
proto addr len
op code
src hardware addr
src proto addr
dst hardware addr
dst proto addr

-
router > routing table > NAT, NAPT


# l4 transport

(icmp)
-
(tcp)
src port
dst port
sequence
confirmation reply number
data offset
reserved
control bit (syn, ack, fin…)
window
checksum
emergency ptr
option
data (payload)
-
(udp)
src port
dst port
len
checksum
data(payload)

```


# LINUX KERNEL MODULE

```shell

lsmod

insmod
rmmod

depmod

modprobe

modprobe -r



```
```shell
# auto load:  insert module load command to

# /etc/modules-load.d/foo.conf
# or
# /etc/modprobe.d/foo.conf
foo

```

```shell

# blacklist: insert line to

# /etc/modules-load.d/foo.conf
# or
# /etc/modprobe.d/foo.conf
blacklist foo

```

```shell

# dkms
# autobuild when kernel update

# add dkms.conf
dkms add . -m $MODULE_NAME -v $VERSION

dkms autoinstall

# or

dkms build $MODULE -v $VERSION

dkms install $MODULE -v $VERSION


```

```shell
# manually create dev without using udev

sudo mknod "${DEVNM}" c ${MAJOR} ${MINOR}

```

# LINUX BOOT

```shell
boot (firm)

bios | uefi -> grub -> vmlinuz, initramfs -> device and drivers -> rootfs mount -> init (pid 1, systemd, user space) -> log in

kernel inspection, cpu, memory, device bus, device, aux kernel subsys(networking...), rootfs, user space

init(systemd)
  systemctl, unit, /etc/systemd, /lib/systemd, /usr/systemd...
    target, service, socket, mount...
```

# GRUB

```shell
# check partition and images

ls

linux (hd0,1)/vmlinuz root=/dev/sda1

initrd (hd0,1)/initrd.img

boot

```

# LINUX KERNEL BUILD

```shell

# packages

sudo apt update


sudo apt install -y git fakeroot build-essential tar ncurses-dev \
    tar xz-utils libssl-dev bc stress python3-distutils libelf-dev \
    linux-headers-$(uname -r) bison flex libncurses5-dev util-linux net-tools "linux-tools-$(uname -r)" exuberant-ctags cscope \
    sysfsutils gnome-system-monitor curl perf-tools-unstable \
    gnuplot rt-tests indent tree psmisc smem libnuma-dev numactl \
    hwloc bpfcc-tools sparse flawfinder cppcheck bsdmainutils \
    trace-cmd virt-what dwarves 


# get source

curl -o /tmp/linux-5.5.1.tar.xz https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.5.1.tar.xz

# or clone

git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

mv /tmp/linux-5.5.1.tar.xz ~

cd ~

tar -xf linux-5.5.1.tar.xz

# default
    LLKD_KSRC="$HOME/linux-5.5.1"
    cp /boot/config-5.4.0-148-generic "$LLKD_KSRC/.config"
    cd "$LLKD_KSRC"
    make menuconfig

# localmod
    LLKD_KSRC="$HOME/linux-5.5.1"
    lsmod > /tmp/lsmod.now
    cd "$LLKD_KSRC"
    make LSMOD=/tmp/lsmod.now localmodconfig
    make menuconfig

# ubuntu specific

scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS

# change config

LLKD_KSRC="$HOME/linux-5.5.1"

cp "$LLKD_KSRC/init/Kconfig" "$LLKD_KSRC/init/Kconfig.orig"

vim "$LLKD_KSRC/init/Kconfig"

# build

cd "$LLKD_KSRC"

time make -j4


# module install

cd "$LLKD_KSRC"

sudo make modules_install

ls /lib/modules


# boot image and initramfs

LLKD_KSRC="$HOME/linux-5.5.1"


cd "$LLKD_KSRC"

sudo make install


# boot update 

sudo cp /etc/default/grub /etc/default/grub.orig

sudo vim /etc/default/grub

sudo update-grub


# ui mode switch

Ctrl + Alt + F2


# make iso

sudo apt install genisofs

mkdir /bck

# with isolinux at the top "/boot" directroy - relative to source path

mkisofs -b boot/isolinux/isolinux.bin -c boot/isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -J -joliet-long -R -x /bck -x /proc -x /tmp -x /mnt -x /dev -x /sys -x /run -x /media -x /var/log -x /var/cache/apt/archives -o /bck/<name>.iso /

# then extract iso using scp or whatever

sudo isohybrid /bck/<output>.iso


```

# LINUX KERNEL BUILD DEB PKG PATCH REAL TIME

```shell


sudo apt install build-essential git libssl-dev libelf-dev flex bison

# first find the closest available rt patch for current kernel(uname -a)
# then get

wget https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.4.143.tar.xz

wget https://mirrors.edge.kernel.org/pub/linux/kernel/projects/rt/5.4/patch-5.4.143-rt64.patch.xz


tar -xf linux-5.4.143.tar.xz
cd linux-5.4.143
xzcat ../patch-5.4.143-rt64-rc2.patch.xz | patch -p1

cp /boot/config-5.4.0-81-generic .config
make oldconfig

# preempt_rt > Y

vim .config

# delete value as below

CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_MODULE_SIG_KEY=""
CONFIG_SYSTEM_REVOCATION_KEYS=""

# comment out

CONFIG_MODULE_SIG_FORCE
CONFIG_DEBUG_INFO_BTF
CONFIG_MODULE_SIG_ALL

# build kernel
# with git repo
make -j4 deb-pkg
# not with git repo
make -j4 bindeb-pkg

# install

sudo dpkg -i ../linux-headers-5.4.143-rt64-rc2_5.4.143-rt64-1_amd64.deb ../linux-image-5.4.143-rt64_5.4.143-rt64-1_amd64.deb ../linux-libc-dev_5.4.143-rt64-1_amd64.deb


reboot

```

# LINUX KERNEL MODULE DRIVER CHANGE

```shell

# net example

sudo mv /lib/modules/$(uname -r)/kernel/drivers/net/igb/igb.ko{,.bak}

echo 'blacklist igb' > /etc/modprobe.d/blacklist.conf

# build and install new driver module

depmod

sudo update-initramfs -c -k $(uname -r)

```


# LINUX DIAGNOSTIC

```shell
journalctl -f
journalctl -xe
journalctl -k
journalctl -b
dmesg
dmest -wH
efibootmgr
```

# LINUX KERNEL PANIC KDUMP

```shell

# should be enabled
# /boot/config-$(uname -r)

CONFIG_RELOCATABLE=y
CONFIG_KEXEC=y
CONFIG_CRASH_DUMP=y
CONFIG_DEBUG_INFO=y


sudo apt update

sudo apt install kdump-tools crash kexec-tools makedumpfile

# dbg symbol package

sudo apt install ubuntu-dbgsym-keyring

sudo echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.list

sudo apt update

sudo apt install linux-image-$(uname -r)-dbgsym

# yes

# reboot

sudo grep USE_KDUMP /etc/default/kdump-tools

sudo grep LOAD_KEXEC /etc/default/kexec

# check

sudo kdump-config show

# after panic and reboot

sudo -i

cd /var/crash/$CRASH_TIMESTAMP

root@ubuntu24-8:/var/crash/xx# ls
dmesg.xx  dump.xx

# read dump

crash /usr/lib/debug/boot/vmlinux-$(uname -r) dump.xx
```

# GCC G++ CLANG COMPILE

```shell

# install 

sudo apt install build-essential clang llvm clang-tidy cppcheck

--std=c99 

--std=c++11

--std=c++14

-g  # for gdb

-Wall

-l # for linking

-c # for unlinked object file

-I # inlcude dir

-L # library directory

-Wl,-rpath=  # library directory (for dynamic loader)

-c -fPIC # for .so

-shared # for .so

# ex) 
# gcc -c -Wall -o solimod.o -fpic lib/sorrylinusmod/mod/solimod.c
# gcc -shared -o libsolimod.so solimod.o

ar rcs # for .a

# ex)
# gcc -c -o out.o out.c
# ar rcs libout.a out.o

-D  # define variable

-fanalyzer # on static analysis

clang-tidy # clang static analysis

clang-tidy src/main.c -- -I.

cppcheck # yet another static analysis

cppcheck --enable=all -I. src/main.c

```


# GDB DEBUGGER C C++ GO BINARY DEBUG

```shell
Startup 
% gdb -help         	print startup help, show switches
*% gdb object      	normal debug 
*% gdb object core 	core debug (must specify core file)
%% gdb object pid  	attach to running process
% gdb        		use file command to load object 

Help
*(gdb) help        	list command classes
(gdb) help running      list commands in one command class
(gdb) help run        	bottom-level help for a command "run" 
(gdb) help info         list info commands (running program state)
(gdb) help info line    help for a particular info command
(gdb) help show         list show commands (gdb state)
(gdb) help show commands        specific help for a show command

Breakpoints
*(gdb) break main       set a breakpoint on a function
*(gdb) break 101        set a breakpoint on a line number
*(gdb) break basic.c:101        set breakpoint at file and line (or function)
*(gdb) info breakpoints        show breakpoints
*(gdb) delete 1         delete a breakpoint by number
(gdb) delete        	delete all breakpoints (prompted)
(gdb) clear             delete breakpoints at current line
(gdb) clear function    delete breakpoints at function
(gdb) clear line        delete breakpoints at line
(gdb) disable 2         turn a breakpoint off, but don't remove it
(gdb) enable 2          turn disabled breakpoint back on
(gdb) tbreak function|line        set a temporary breakpoint
(gdb) commands break-no ... end   set gdb commands with breakpoint
(gdb) ignore break-no count       ignore bpt N-1 times before activation
(gdb) condition break-no expression         break only if condition is true
(gdb) condition 2 i == 20         example: break on breakpoint 2 if i equals 20
(gdb) watch expression        set software watchpoint on variable
(gdb) info watchpoints        show current watchpoints

Running the program
*(gdb) run        	run the program with current arguments
*(gdb) run args redirection        run with args and redirection
(gdb) set args args...        set arguments for run 
(gdb) show args        show current arguments to run
*(gdb) cont            continue the program
*(gdb) step            single step the program; step into functions
(gdb) step count       singlestep \fIcount\fR times
*(gdb) next            step but step over functions 
(gdb) next count       next \fIcount\fR times
*(gdb) CTRL-C          actually SIGINT, stop execution of current program 
*(gdb) attach process-id        attach to running program
*(gdb) detach        detach from running program
*(gdb) finish        finish current function's execution
(gdb) kill           kill current executing program 

Core 
(gdb) generate-core-file  generate core dump file

Thread
(gdb) info threads             get threads 
(gdb) thread id                switch to thread with id
(gdb) thread apply id action   apply action to thread id

Stack backtrace
*(gdb) bt        	print stack backtrace
(gdb) frame        	show current execution position
(gdb) up        	move up stack trace  (towards main)
(gdb) down        	move down stack trace (away from main)
*(gdb) info locals      print automatic variables in frame
(gdb) info args         print function parameters 

Browsing source
*(gdb) list 101        	list 10 lines around line 101
*(gdb) list 1,10        list lines 1 to 10
*(gdb) list main  	list lines around function 
*(gdb) list basic.c:main        list from another file basic.c
*(gdb) list -        	list previous 10 lines
(gdb) list *0x22e4      list source at address
(gdb) cd dir        	change current directory to \fIdir\fR
(gdb) pwd          	print working directory
(gdb) search regexpr    forward current for regular expression
(gdb) reverse-search regexpr        backward search for regular expression
(gdb) dir dirname       add directory to source path
(gdb) dir        	reset source path to nothing
(gdb) show directories        show source path

Browsing Data
*(gdb) print expression        print expression, added to value history
*(gdb) print/x expressionR        print in hex
(gdb) print array[i]@count        artificial array - print array range
(gdb) print $        	print last value
(gdb) print *$->next    print thru list
(gdb) print $1        	print value 1 from value history
(gdb) print ::gx        force scope to be global
(gdb) print 'basic.c'::gx        global scope in named file (>=4.6)
(gdb) print/x &main     print address of function
(gdb) x/countFormatSize address        low-level examine command
(gdb) x/x &gx        	print gx in hex
(gdb) x/4wx &main       print 4 longs at start of \fImain\fR in hex
(gdb) x/gf &gd1         print double
(gdb) help x        	show formats for x
*(gdb) info locals      print local automatics only
(gdb) info functions regexp         print function names
(gdb) info variables  regexp        print global variable names
*(gdb) ptype name        print type definition
(gdb) whatis expression       print type of expression
*(gdb) set variable = expression        assign value
(gdb) display expression        display expression result at stop
(gdb) undisplay        delete displays
(gdb) info display     show displays
(gdb) show values      print value history (>= gdb 4.0)
(gdb) info history     print value history (gdb 3.5)

Object File manipulation
(gdb) file object      		load new file for debug (sym+exec)
(gdb) file             		discard sym+exec file info
(gdb) symbol-file object        load only symbol table
(gdb) exec-file object 		specify object to run (not sym-file)
(gdb) core-file core   		post-mortem debugging

Signal Control
(gdb) info signals        	print signal setup
(gdb) handle signo actions      set debugger actions for signal
(gdb) handle INT print          print message when signal occurs
(gdb) handle INT noprint        don't print message
(gdb) handle INT stop        	stop program when signal occurs
(gdb) handle INT nostop         don't stop program
(gdb) handle INT pass        	allow program to receive signal
(gdb) handle INT nopass         debugger catches signal; program doesn't
(gdb) signal signo        	continue and send signal to program
(gdb) signal 0        		continue and send no signal to program

Machine-level Debug
(gdb) info registers        	print registers sans floats
(gdb) info all-registers        print all registers
(gdb) print/x $pc        	print one register
(gdb) stepi        		single step at machine level
(gdb) si        		single step at machine level
(gdb) nexti        		single step (over functions) at machine level
(gdb) ni        		single step (over functions) at machine level
(gdb) display/i $pc        	print current instruction in display
(gdb) x/x &gx        		print variable gx in hex
(gdb) info line 22        	print addresses for object code for line 22
(gdb) info line *0x2c4e         print line number of object code at address
(gdb) x/10i main        	disassemble first 10 instructions in \fImain\fR
(gdb) disassemble addr          dissassemble code for function around addr

History Display
(gdb) show commands        	print command history (>= gdb 4.0)
(gdb) info editing       	print command history (gdb 3.5)
(gdb) ESC-CTRL-J        	switch to vi edit mode from emacs edit mode
(gdb) set history expansion on       turn on c-shell like history
(gdb) break class::member       set breakpoint on class member. may get menu
(gdb) list class::member        list member in class
(gdb) ptype class               print class members
(gdb) print *this        	print contents of this pointer
(gdb) rbreak regexpr     	useful for breakpoint on overloaded member name

Miscellaneous
(gdb) define command ... end        define user command
*(gdb) RETURN        		repeat last command
*(gdb) shell command args       execute shell command 
*(gdb) source file        	load gdb commands from file
*(gdb) quit        		quit gdb

```


# VALGRIND DYNAMIC ANALYSIS

```shell

valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose ./main.out 


```

# CORE DUMP

```shell

# check

ulimit -c

# set unlimited 

ulimit -c unlimited


```

# SYSTEMCTL SYSTEMD

```shell
# /root/1234.sh

ncat -lv 1234

```

```shell

/etc/systemd/system/nc1234.service
```


```shell
# /etc/systemd/system/nc1234.service

[Unit]
Description=nc1234 demo service
After=network.target
StartLimitIntervalSec=0
[Service]
Type=simple
Restart=always
RestartSec=1
User=root
ExecStart=/root/1234.sh

[Install]
WantedBy=multi-user.target

```

```shell
systemctl enable nc1234

systemctl start nc1234

```

# CPU NUMA 

```shell

# from numa nodes 0,1 use 1 if possible
numactl --cpubind=0,1 --preferred=1 $EXECUTABLE


```


# EBPF LINUX LIBBPF



```shell


# install bcc
# ubuntu 22.04

sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf


git clone https://github.com/iovisor/bcc.git

mkdir bcc/build
cd bcc/build
cmake ..
make
sudo make install

# build python3 binding

cmake -DPYTHON_CMD=python3 .. 
pushd src/python/
make
sudo make install
popd


```


```shell
# libbpf

apt install clang libelf1 libelf-dev zlib1g-dev

git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap

cd libbpf-bootstrap 

git submodule update --init --recursive   



```


# XDP LINUX EBPF

```shell
# in project dir ex) xdp

git clone https://github.com/xdp-project/xdp-tools

# git clone https://github.com/libbpf/libbpf

sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386 m4

# To install the ‘perf’ utility, run this on Debian:

sudo apt install linux-perf
# or this on Ubuntu:

sudo apt install linux-tools-$(uname -r)

# kernel header

sudo apt install linux-headers-$(uname -r)

# etc

sudo apt install linux-tools-common linux-tools-generic
sudo apt install tcpdump


cd xdp-tools

./configure

make

sudo make install

cd lib/libbpf/src

sudo make install

# compile 

clang -O2 -g -Wall -c -target bpf -o test_xdp.o test_xdp.c

# create veth or on interface

# load module

sudo ip link set veth1 xdpgeneric obj test_xdp.o sec xdp_drop

# or

sudo xdp-loader load -m skb -s xdp_drop veth1 test_xdp.o


# unload

sudo ip link set veth1 xdpgeneric off

# or 

sudo xdp-loader unload -a veth1

# check 

sudo bpftool map show

sudo bpftool map dump id 13

# bpf printk out

sudo cat /sys/kernel/tracing/trace

```

 
# GIT

```shell

# local branch

git switch -c <loc_name> <remote_name>/<branch>

# local merge
# on target branch

git merge <loc_name>

# on forked remote branch's local branch
# pulling equivalent

git remote add <upstream_name> <upstream_addr>

git fetch <upstream_name>

git rebase <upstream_name>/<branch>

git add .

git commit

git push -f <forked_origin> <forked_origin_branch>

# git push create set to public

git push -o repo.private=false -u origin main

# then PR

# squash commits

git log

git reset --soft HEAD~<last_commits_count>

ex) git reset --soft HEAD~5

# config 

git config --global credential.helper store

# then clone or pull or whatever to store

# squash commits using editor

git rebase -i my_first_commit~

# prefix `pick` to use commit
# prefix `squash` to get it meld into previous commit


# git diff


git diff commit_a commit_b

# or just the current and latest commit

git diff


# git create patch file for latest commit

git format-patch -1 HEAD

# signoff

git commit --signoff

# stat patch before applying

git apply --stat a_file.patch

# check patch before applying

git apply --check a_file.patch

# apply patch 

git am --signoff < a_file.path

# git submodule

git submodule add <repository.git>

# git submodule pull all

git submodule update --recursive

# git submodule clone

git clone <repository.git>

git submodule init

git submodule update

# private repo
# automatic with go

git config --global set url."https://$ID:$PW@github.com/org".instreadOf "https://github.com/org"

# github workflow self hosted runner 

# Create a folder
mkdir actions-runner && cd actions-runner

# Download the latest runner package

curl -o actions-runner-linux-x64-2.306.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.306.0/actions-runner-linux-x64-2.306.0.tar.gz

# Optional: Validate the hash

echo "b0a090336f0d0a439dac7505475a1fb822f61bbb36420c7b3b3fe6b1bdc4dbaa  actions-runner-linux-x64-2.306.0.tar.gz" | shasum -a 256 -c

# Extract the installer

tar xzf ./actions-runner-linux-x64-2.306.0.tar.gz

# Create the runner and start the configuration experience

./config.sh --url https://github.com/seantywork/k8s-base-cluster-setup --token <TOKEN>

# Last step, run it!

./run.sh

```


```shell

# install github cli

curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg 

sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null 

sudo apt update

sudo apt install gh -y

```

```shell

# some commands

gh pr list

gh pr edit <num> --add-reviewer seantywork

gh pr edit <num> --add-assignee seantywork

gh pr merge <num> --merge

gh pr view <num> --json state,author,assignees,reviews,reviewRequests,mergeable

```

```shell

# git lfs

git lfs install


git lfs track "*.png" "*.jpg" "*.docx" "*.zip"

git add .

git commit -m "lfs"



```


```shell

# git server

# on git server

sudo mkdir /git


sudo adduser git

sudo chown git:git /git

su git
cd
mkdir .ssh && chmod 700 .ssh
touch .ssh/authorized_keys && chmod 600 .ssh/authorized_keys


cd /git

mkdir boxproject.git

git init --bare



# on git user computer

ssh-copy-id git@gitserver

mkdir boxproject

git init
git add .
git commit -m 'init'
git branch -M main
git remote add origin git@gitserver:/git/boxproject.git
git push -u origin main


# on another user computer


git clone git@gitserver:/git/boxproject.git

cd boxproject

git fetch --all

git switch -c main origin/main

```

```shell

# remove submodule

# delete in .gitmodules 

git add .gitmodules

# delete in .git/config.

git rm --cached path_to_submodule 

rm -rf .git/modules/path_to_submodule

git commit -m "Removed submodule <name>"

rm -rf path_to_submodule

```


```shell

# git email

sudo apt update

sudo apt install git-email

# might have to install perl dependency

cpan Authen::SASL MIME::Base64 Net::SMTP::SSL

# configure $HOME/.gitconfig

[sendemail]
    smtpServer = smtp.gmail.com
    smtpServerPort = 587
    smtpEncryption = tls
    smtpUser = my_email@gmail.com
    # (Optional: we'll leave this commented out and use a different way)
    # smtpPass = PASSWORD

# generate google app password for gmail
# goto acoount manager, search app password

# add pass to .gitconfig

git send-email --to=my_email@gmail.com something.patch

```


# CGROUP

```shell
# cgroup 

# check cgroup mount location

mount | grep cgroup2

# if not change kernel parameters in grub to see

# cgroup_no_v1=all

cat /proc/cmdline

# check controllers

cat /sys/fs/cgroup/cgroup.controllers

# add controller , here SOMETHING being cpu 

echo "+$SOMETHING" >> /sys/fs/cgroup/cgroup.subtree_control  

# add sub group

mkdir /sys/fs/cgroup/$SOME_GROUP

# give cpu max

echo "$MAX $PERIOD" > /sys/fs/cgroup/$SOME_GROUP/cpu.max

# revoke group

rmdir /sys/fs/cgroup/$SOME_GROUP


```


# PROCESS NAMESPACE

```shell


unshare --user --pid --map-root-user --mount-proc --fork bash 

```

# OVERLAYFS

```shell
sudo mkdir /tmp/upper /tmp/overlay /mnt/merged_directories

sudo mount -t overlay overlay -olowerdir=/path/to/dir1:/path/to/dir2,upperdir=/tmp/upper,workdir=/tmp/overlay /mnt/merged_directories

```

# NETWORK NAMESPACE

```shell

# bridge, veth with peer

sudo ip link add br-blah01 type bridge 

sudo ip link add dev vm1 type veth peer name vm2

sudo ip link set vm1 master br-blah01

sudo ip addr add 10.0.0.1/24 dev br-blah01

sudo ip addr add 10.0.0.2/24 dev vm2

sudo ip link set br-blah01 up

sudo ip link set vm1 up

sudo ip link set vm2 up

# veth with peer namespace 

sudo ip netns add blahnet

sudo ip link set vm2 netns blahnet 

sudo ip netns exec blahnet ip link set dev lo up

sudo ip netns exec blahnet ip a

sudo iptables -t nat -A POSTROUTING -o br-blah01 -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o wlo1 -j MASQUERADE

sudo ip netns exec blahnet /bin/bash

ip addr add 10.0.0.2/24 dev vm2

ip link set dev vm2 up

ip route add default via 10.0.0.1

echo "nameserver 8.8.8.8" >> /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf

```


# ROUTER/MODEM LAN

```shell


 

ethernet 

 

wifi 


mac

ip
 

dns (check /etc/resolv.conf) 

 

dhcp (alongside static) 

# ethernet wan

 plug the cable into wan port

# ethernet hub/ap mode & ethernet extension

 turn off dhcp, enable hub/ap mode

 set internal new ip avoiding collision, under the default gateway cidr, set default gateway and dns

 plug the cable into lan port


# wireless wan

wifi wan

dont turn off dhcp

set internal new ip, for a new cidr range connect to the main ap with wisp


# wireless multibridge

wifi extension

set internal new ip avoiding collision, under the default gateway cidr

turn off dhcp

connect to the main ap with repeater


port forward 



```

# NETWORK INTERFACE ADDRESS NETPLAN SYSTEMD-NETWORKD

```shell

# netplan

# below is the default configuration

# craete other ones if needed

```
```shell
# /etc/netplan/01-network-manager-all.yaml 

network:
 version: 2
 renderer: NetworkManager # or systemd-networkd
 ethernets:  # or wifis, bridges, modems
   eth0:
     dhcp4: no 
     addresses: [172.23.207.254/20]
     gateway4: 192.168.1.1
     nameservers:
         addresses: [8.8.8.8,8.8.8.4]
```
```shell
sudo netplan try

# sudo netplan generate
sudo netplan apply
```


```shell

# disable cloud init network config if necessary



```

```shell

sudo nano /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg

network: {config: disabled}

```

```shell

# /etc/network/interfaces

auto eth0
iface eth0 inet static 
address 192.168.2.1
netmask 255.255.255.0
gateway 192.1.2.254

# or dhcp

auto eth0
iface eth0 inet dhcp


```


```shell

# /etc/NetworkManager


```

# DISABLE/ENABLE WIFI IF

```shell
# disable
```

```shell
# /etc/network/interfaces
iface <interface_name> inet manual
```

```shell
# enable
# undo above

```
# ARP

```shell

# delete 
sudo ip -s -s neigh flush all

arp -d 192.168.1.1

# add

arp -i interface -s ip mac

```

```shell
# longer cache expiration

net.ipv4.neigh.default.gc_stale_time=57600

# larger garbage collection threshold

net.ipv4.neigh.default.gc_thresh1 = 32768
net.ipv4.neigh.default.gc_thresh2 = 32768
net.ipv4.neigh.default.gc_thresh3 = 32768


```

# REDIRECT

```shell

sysctl -w net.ipv4.conf.enp134s0f2.accept_redirects=0
sysctl -w net.ipv4.conf.enp134s0f2.send_redirects=0
sysctl -w net.ipv4.conf.enp134s0f0.accept_redirects=0
sysctl -w net.ipv4.conf.enp134s0f0.send_redirects=0


```

# ETHTOOL


```shell

# queue

ethtool -l devname 

# only use one combined rxtx channel

ethtool -L devname combined 1


```

```shell

# ring buffer

ethtool -G enp134s0f0 rx 4096
ethtool -G enp134s0f0 tx 4096
ethtool -G enp134s0f2 rx 4096
ethtool -G enp134s0f2 tx 4096

```

```shell

# flow

ethtool -N eth0 rx-flow-hash udp4 fn
ethtool -N eth0 flow-type udp4 src-port 4242 dst-port 4242 action 16

```


# IP INTERFACE IPTABLES NAT PORT FORWARD NETFILTER

```shell

# link, addr

sudo modprobe dummy

sudo ip link add deth0 type dummy

sudo ip link set dev deth0 address C8:D7:4A:4E:47:50

sudo ip addr add 192.168.1.100/24 brd + dev deth0 # label deth0:0

sudo ip link set dev deth0 up

sudo ip link set dev deth0 down

sudo ip addr del 192.168.1.100/24 brd + dev deth0 # label deth0:0

sudo ip link delete deth0 type dummy

sudo modprobe -r dummy

# route

# to NAT

ip addr add 192.168.10.2/24 dev enp3s0

ip link set dev enp3s0 up

# enp3s0 being the interface the router is connected to
# router WAN IP being 192.168.10.2/24 or something
# router default gateway 192.168.10.1
# router LAN IP being 192.168.100.1/24 or something

# from NAT

ip route add 192.168.10.0/24 via 192.168.100.1 dev eth0

# eth0 being an interface with a connection to the router
# using eth0 gateway router (192.168.100.1) to route to 192.168.10.0/24 network

# route with table 
# ex) add rule as table number 5

ip route add 192.168.10.0/24 dev enp3s0 table 5

# flush to apply 

ip route flush cache

# nexthop different network

sudo ip route add 192.168.122.87 dev enp1s0

sudo ip route add 10.0.2.0/24 via 192.168.122.87 dev enp1s0

# rule 

# all 

ip rule add preference 100 from all lookup 5

# fwmark
# ex) lookup table 5 if marked 5 

ip rule add preference 100 fwmark 5 table 5

# by source 

ip rule add preference 100 from 192.168.0.0/24 lookup 100

```

```shell

# forward

# ephemeral

echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# permanent
cat <<EOF | sudo tee /etc/sysctl.d/99-ipv4-forward.conf
net.ipv4.ip_forward                 = 1
EOF

cat <<EOF | sudo tee /etc/sysctl.d/99-ipv6-forward.conf
net.ipv6.conf.all.forwarding                 = 1
EOF

sudo sysctl -p

sudo sysctl --system

```
```shell

# routing steps

# incoming mangle prerouting, fwmark

sudo iptables -t mangle -A PREROUTING -p udp -s 192.168.10.5 -j MARK --set-mark 5

# incoming prerouting

sudo iptables -t nat -A PREROUTING -i wlo1 -p tcp --dport 8888 -j DNAT --to-destination 192.168.1.100:8000

# route decision incoming

# incoming input 

sudo iptables -t nat -A INPUT -i enp3s0 -p udp -s 192.168.10.5 -j SNAT --to-source 192.168.10.50


# route forward if no local 

# forward init rule
sudo iptables -A FORWARD -i wlo1 -o deth0 -p tcp --syn --dport 8888 -m conntrack --ctstate NEW -j ACCEPT

# forward allow all tcp init rule

sudo iptables -A FORWARD -i wlo1 -o deth0 -p tcp -m conntrack --ctstate NEW -j ACCEPT

# forward rules
sudo iptables -A FORWARD -i wlo1 -o deth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -A FORWARD -i deth0 -o wlo1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# forward default DROP

sudo iptables -P FORWARD DROP


# outgoing mangle output 

sudo iptables -t mangle -A OUTPUT -p udp -d 192.168.10.5 -j MARK --set-mark 5

# outgoing output 

sudo iptables -t nat -A OUTPUT -p udp -d 192.168.10.50 -j DNAT --to-destination 192.168.10.5

# route decision out

# outbound including forward

# outgoing postrouting

sudo iptables -t nat -A POSTROUTING -o wlo1 -p tcp -j MASQUERADE

# outgoing postrouting

sudo iptables -t nat -A POSTROUTING -o wlo1 -p tcp -s 192.168.10.50 -j SNAT --to-source 192.168.10.5


# permanent rule

sudo service netfilter-persistent save

# delete 

sudo iptables -S 

iptables -L -n -t nat

sudo iptables -D [ -t nat ] $A_SPEC

# or

sudo iptables -L --line-numbers

sudo iptables -D INPUT $LINE_NUM


# netfilter queue

sudo iptables -I FORWARD -p tcp -j NFQUEUE --queue-num 100

# netfilter queue dev

sudo apt install libnetfilter-queue-dev

```


```shell

# gateway - LAN route scenario
sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up veth2

sudo ip addr add 192.168.62.5/24 dev veth1

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth2


sudo ip netns add net2

sudo ip link add dev veth21 type veth peer name veth22 netns net2

sudo ip link set up veth21

sudo ip netns exec net2 ip link set up veth22

sudo ip addr add 192.168.26.5/24 dev veth21

sudo ip netns exec net2 ip addr add 192.168.26.6/24 dev veth22

sudo sysctl -w net.ipv4.ip_forward=1

sudo iptables -P FORWARD ACCEPT

sudo ip netns exec net1 ip route add 192.168.26.0/24 via 192.168.62.5 dev veth2

sudo ip netns exec net2 ip route add 192.168.62.0/24 via 192.168.26.5 dev veth22

```

```shell
# gateway - WAN route scenario 

sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up veth2

sudo ip netns exec net1 ip link set up lo

sudo ip addr add 192.168.62.5/24 dev veth1

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth2

sudo ip netns exec net1 ip route add default via 192.168.62.5 dev veth2

sudo ip route add 192.168.64.0/24 via 192.168.62.6 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net1 ip link set up veth3

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net1 ip addr add 192.168.122.1/24 dev veth3

sudo ip netns exec net2 ip addr add 192.168.122.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.122.1 dev veth4

sudo ip netns exec net1 ip route add 192.168.122.0/24 via 192.168.122.1 dev veth3

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1


sudo ip netns exec net1 iptables -P FORWARD ACCEPT


sudo iptables -I FORWARD -p all -i veth1 -m conntrack --ctstate NEW -j ACCEPT

sudo iptables -I FORWARD -p all -i veth1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -I FORWARD -p all -o veth1 -m conntrack --ctstate NEW -j ACCEPT

sudo iptables -I FORWARD -p all -o veth1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -t nat -I POSTROUTING -p all -o veth1 -j MASQUERADE

sudo iptables -t nat -I POSTROUTING -p all -o ens3 -j MASQUERADE


sudo iptables -P FORWARD DROP

sudo ip rule add preference 200 from all lookup 200 

sudo ip route add 192.168.122.6/32 via 192.168.62.6 dev veth1 table 200

```

```shell

# gateway - forward scenario

sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up veth2

sudo ip netns exec net1 ip link set up lo

sudo ip addr add 192.168.62.5/24 dev veth1

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth2

sudo ip netns exec net1 ip route add default via 192.168.62.5 dev veth2

# sudo ip route add 192.168.64.0/24 via 192.168.62.6 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net1 ip link set up veth3

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net1 ip addr add 192.168.64.1/24 dev veth3

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.64.6 dev veth4

sudo ip netns exec net1 ip route add 192.168.64.0/24 via 192.168.64.1 dev veth3

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1


#tcp

sudo ip netns exec net1 iptables -t nat -I PREROUTING -p tcp --dport 8888 -j DNAT --to-destination 192.168.64.6:8000


sudo ip netns exec net1 iptables -I FORWARD -p tcp --syn -i veth3 -m conntrack --ctstate NEW -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp -i veth3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp --syn -o veth3 -m conntrack --ctstate NEW -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp -o veth3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


sudo ip netns exec net1 iptables -P FORWARD DROP

#sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p tcp -o veth3 -j SNAT --to-source 192.168.64.1

# or

sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p tcp -o veth2 -j MASQUERADE

sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p tcp -o veth3 -j MASQUERADE

```



```shell

# gateway - NAT scenario

sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up veth2

sudo ip netns exec net1 ip link set up lo

sudo ip addr add 192.168.62.5/24 dev veth1

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth2

sudo ip netns exec net1 ip route add default via 192.168.62.5 dev veth2

sudo ip route add 192.168.64.0/24 via 192.168.62.6 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net1 ip link set up veth3

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net1 ip addr add 192.168.64.1/24 dev veth3

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.64.6 dev veth4

sudo ip netns exec net1 ip route add 192.168.64.0/24 via 192.168.64.1 dev veth3

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1

#tcp


sudo ip netns exec net1 iptables -I FORWARD -p tcp --syn -i veth2 -m conntrack --ctstate NEW -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp -i veth2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp --syn -o veth2 -m conntrack --ctstate NEW -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp -o veth2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p tcp -o veth3 -j MASQUERADE

sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p tcp -o veth2 -j MASQUERADE


#all


#sudo ip netns exec net1 iptables -I FORWARD -p all -i veth2 -m conntrack --ctstate NEW -j ACCEPT

#sudo ip netns exec net1 iptables -I FORWARD -p all -i veth2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

#sudo ip netns exec net1 iptables -I FORWARD -p all -o veth2 -m conntrack --ctstate NEW -j ACCEPT

#sudo ip netns exec net1 iptables -I FORWARD -p all -o veth2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

#sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p all -o veth3 -j MASQUERADE

#sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p all -o veth2 -j MASQUERADE


sudo ip netns exec net1 iptables -P FORWARD DROP

```

```shell

# gateway - bridge scenario


sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up lo

sudo ip addr add 192.168.64.1/24 dev veth1

sudo ip route add 192.168.64.0/24 via 192.168.64.2 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.64.1 dev veth4

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1


sudo ip netns exec net1 ip link add br0 type bridge stp_state 0

sudo ip netns exec net1 ip link set br0 address 12:34:56:78:9a:bc

sudo ip netns exec net1 ip link set veth2 master br0 

sudo ip netns exec net1 ip link set veth3 master br0

sudo ip netns exec net1 ip addr add 192.168.64.2/24 dev br0

sudo ip netns exec net1 ip link set br0 up

sudo ip netns exec net1 ip link set veth2 up 

sudo ip netns exec net1 ip link set veth3 up

sudo ip netns exec net1 ip route add default via 192.168.64.1 dev br0

sudo ip netns exec net1 ip route add 192.168.64.0/24 via 192.168.64.2 dev br0 proto static


```

```shell

# gateway - bridge vlan trunk scenario


sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up lo

sudo ip addr add 192.168.64.1/24 dev veth1

sudo ip route add 192.168.64.0/24 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.64.1 dev veth4

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1


sudo ip netns exec net1 ip link add br0 type bridge stp_state 0

sudo ip netns exec net1 ip link set br0 address 12:34:56:78:9a:bc

sudo ip netns exec net1 ip link set veth2 master br0 

sudo ip netns exec net1 ip link set veth3 master br0

sudo ip netns exec net1 ip addr add 192.168.64.2/24 dev br0

sudo ip netns exec net1 ip link set br0 up

sudo ip netns exec net1 ip link set veth2 up 

sudo ip netns exec net1 ip link set veth3 up

#sudo ip netns exec net1 ip route add default via 192.168.64.1 dev br0

sudo ip netns exec net1 ip route add default dev br0

sudo ip netns exec net1 ip route add 192.168.64.0/24 dev br0 proto static


# 

sudo ip netns exec net1 ip link set br0 type bridge vlan_filtering 1

sudo ip netns add net3

sudo ip link add dev veth5 type veth peer name veth6 netns net3

sudo ip link set veth5 netns net1

sudo ip netns exec net1 ip link set veth5 master br0

sudo ip netns exec net1 ip link set veth5 up

sudo ip netns exec net3 ip link set up veth6

sudo ip netns exec net3 ip addr add 192.168.66.6/24 dev veth6

sudo ip netns exec net3 ip link set dev veth6 up

sudo ip netns exec net3 ip route add default via 192.168.66.1 dev veth6

sudo ip netns exec net1 bridge vlan add dev veth5 vid 5 pvid untagged master

sudo ip netns exec net1 bridge vlan add dev veth2 vid 5 master

sudo ip netns exec net1 ip route add 192.168.66.0/24 dev br0 proto static


#

sudo ip link add link veth1 name veth1.5 type vlan id 5

sudo ip addr add 192.168.66.1/24 dev veth1.5

sudo ip link set veth1.5 up

```


```shell
# gateway redirect scenario 


# 10.168.0.29 being NAT 

# 10.168.0.26 being default gateway 

# 10.168.0.100 being default gateway's default gateway

# on NAT 

sudo ip netns add vnet 

sudo ip link set enp7s0 netns vnet 

sudo ip netns exec vnet ip addr add 10.168.0.29/24 dev enp7s0

sudo ip netns exec vnet ip link set up dev enp7s0 

sudo ip netns exec vnet ip route add default via 10.168.0.26
 
# on default gateway 

sudo ip rule add preference 221 from 10.168.0.0/24 lookup 221

sudo ip route add default via 10.168.0.100 dev enp7s0 table 221

echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects


```

```shell

# host to different NAT with same ip scenario

# nat1
sudo ip netns add net0

sudo ip link add dev veth01 type veth peer name veth02 netns net0

sudo ip link set up veth01

sudo ip netns exec net0 ip link set up veth02

sudo ip addr add 192.168.10.20/24 dev veth01

sudo ip netns exec net0 ip addr add 192.168.10.2/24 dev veth02

# nat2

sudo ip netns add net1

sudo ip link add dev veth11 type veth peer name veth12 netns net1

sudo ip link set up veth11

sudo ip netns exec net1 ip link set up veth12

sudo ip addr add 192.168.10.30/24 dev veth11

sudo ip netns exec net1 ip addr add 192.168.10.2/24 dev veth12

sudo ip rule add preference 100 from all lookup local

sudo ip rule del preference 0

sudo ip rule add preference 92 fwmark 2 table 92
sudo ip rule add preference 93 fwmark 3 table 93

sudo ip route add default via 192.168.10.20 dev veth01 table 92
sudo ip route add default via 192.168.10.30 dev veth11 table 93


sudo iptables -t nat -A INPUT -p tcp -i veth02 -j SNAT --to-source 192.168.10.3
sudo iptables -t mangle -A OUTPUT -p tcp -d 192.168.10.2 -j MARK --set-mark 2
sudo iptables -t mangle -A OUTPUT -p tcp -d 192.168.10.3 -j MARK --set-mark 3
sudo iptables -t nat -A OUTPUT -p tcp -d 192.168.10.3 -j DNAT --to-destination 192.168.10.2

sudo ip route flush cache


# test

# in net0
sudo ip netns exec net0 nc -l 192.168.10.2 9999

# in net1 
sudo ip netns exec net1 nc -l 192.168.10.2 9999

# on host
nc 192.168.10.2 9999 

# on host
nc 192.168.10.3 9999


```

```shell

# network namespace

sudo ip netns add net1

sudo ip netns del net1

sudo ip -all netns exec ip link show

# veth namespace

ip link add veth1 netns net1 type veth

ip link add veth1 netns net1 type veth peer name veth2 netns net2

# veth

sudo ip link add veth1 type veth


sudo ip addr add 192.168.1.1/24 brd + dev veth0

sudo ip addr add 192.168.1.5/24 brd + dev veth1

sudo ip link set dev veth0 up

sudo ip link set dev veth1 up

sudo ip link set dev veth1 down

sudo ip link set dev veth0 down

sudo ip addr del 192.168.1.1/24 brd + dev veth0

sudo ip addr del 192.168.1.5/24 brd + dev veth1

sudo ip link del veth1 type veth

# veth with peer

sudo ip link add br-blah01 type bridge 

sudo ip link add dev vm1 type veth peer name vm2

sudo ip link set vm1 master br-blah01

sudo ip addr add 10.0.0.1/24 dev br-blah01

sudo ip addr add 10.0.0.2/24 dev vm2

sudo ip link set br-blah01 up

sudo ip link set vm1 up

sudo ip link set vm2 up


```
```shell

# bridge

sudo ip link add br0 type bridge 

ip link set br0 type bridge stp_state 1

# ip link set br0 type bridge vlan_filtering 1

ip link set eth1 master br0

ip link set eth1 up

ip link set br0 up


```

```shell

# tuntap

sudo ip tuntap add mode tap tap0

sudo ip addr add 192.168.1.100/24 brd + dev tap0

sudo ip link set tap0 master br0

sudo ip link set dev tap0 up

```


```shell

# vlan

sudo apt-get install vlan

sudo modprobe 8021q

# permanent

echo "8021q" >> /etc/modules

sudo ip link add link eth0 name eth0.100 type vlan id 5

sudo ip link set eth0.100 up





# del

sudo ip link set eth0.100 down

sudo ip link del eth0.100


```


```shell

# vxlan

# on host1

sudo ip netns add top

sudo ip link add top-in type veth peer name top-out

sudo ip link set top-in netns top

sudo ip netns exec top ip addr add 10.10.5.2/16 dev top-in

sudo ip netns exec top ip link set top-in up

# on host1: bridge

sudo ip link add middle type bridge

sudo ip addr add 10.10.5.1/16 dev middle

sudo ip link set top-out master middle

sudo ip link set top-out up

sudo ip link set middle up

# on host1: route

sudo ip netns exec top ip route add default via 10.10.5.1

# on host1: vxlan

sudo ip link add vxlan-top type vxlan id 100 local 192.168.99.1 remote 192.168.99.2 dev eth0

sudo ip link set vxlan-top master middle

sudo ip link set vxlan-top up


# on host2

sudo ip netns add bottom

sudo ip link add bottom-in type veth peer name bottom-out

sudo ip link set bottom-in netns bottom

sudo ip netns exec bottom ip addr add 10.10.5.12/16 dev bottom-in

sudo ip netns exec bottom ip link set bottom-in up

# on host2: bridge

sudo ip link add middle type bridge

sudo ip addr add 10.10.5.11/16 dev middle

sudo ip link set bottom-out master middle

sudo ip link set bottom-out up

sudo ip link set middle up

# on host2: route

sudo ip netns exec bottom ip route add default via 10.10.5.11


# on host1: vxlan

sudo ip link add vxlan-bottom type vxlan id 100 local 192.168.99.2 remote 192.168.99.1 dev eth0

sudo ip link set vxlan-bottom master middle

sudo ip link set vxlan-bottom up

# test

# on host1
sudo ip netns exec top ncat -l 10.10.5.2 9999

# on host2


sudo ip netns exec bottom ncat 10.10.5.2 9999

```


```shell
# macvlan

ip link add macvlan1 link eth0 type macvlan mode bridge

ip netns add net1

ip link set macvlan1 netns net1

ip netns exec net1 ip link set macvlan1 up 

ip netns exec net1 ip link addr add 192.168.0.16 dev macvlan1


```

```shell

# bond 

#ip link add bond1 type bond miimon 100 mode active-backup
ip link add bond1 type bond miimon 100 mode balance-xor
ip link addr add $ETH0_ADDR dev bond1 
ip link set eth0 master bond1
ip link set eth1 master bond1
ip link set bond1 up
```

```shell

# netkit

sudo ip netns add net1

sudo ip link add nkpeer0 type netkit

sudo ip link set nkpeer0 netns net1

sudo ip link set dev nk0 up

sudo ip netns exec net1 ip link set dev nkpeer0 up

sudo ip addr add 10.168.0.1/24 dev nk0

sudo ip netns exec net1 ip addr add 10.168.0.2/24 dev nkpeer0


```

```shell


# xfrm

# xfrm ip addr


sudo ip netns add vnet
sudo ip link add dev veth01 type veth peer name veth02 netns vnet
sudo ip addr add 192.168.10.1/24 dev veth01
sudo ip addr add 10.168.66.1/24 dev veth01
sudo ip link set up veth01
sudo ip netns exec vnet ip addr add 192.168.10.2/24 dev veth02
sudo ip netns exec vnet ip addr add 10.168.66.2/24 dev veth02
sudo ip netns exec vnet ip link set up veth02

# xfrm state, policy

# client

ip xfrm state add \
    src 10.168.66.1/24 dst 10.168.66.2/24 proto esp spi 0x01000000 reqid 0x01000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.1/24 dst 10.168.66.2/24 


ip xfrm state add \
    src 10.168.66.2/24 dst 10.168.66.1/24 proto esp spi 0x02000000 reqid 0x02000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.2/24 dst 10.168.66.1/24 

ip xfrm policy add \
    src 10.168.66.1/24 dst 10.168.66.2/24 dir out \
    tmpl src 10.168.66.1/24 dst 10.168.66.2/24 proto esp reqid 0x01000000 mode tunnel

ip xfrm policy add \
    src 10.168.66.2/24 dst 10.168.66.1/24 dir in \
    tmpl src 10.168.66.2/24 dst 10.168.66.1/24 proto esp reqid 0x02000000 mode tunnel


# server

ip netns exec vnet ip xfrm state add \
    src 10.168.66.1/24 dst 10.168.66.2/24 proto esp spi 0x01000000 reqid 0x01000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.1/24 dst 10.168.66.2/24


ip netns exec vnet ip xfrm state add \
    src 10.168.66.2/24 dst 10.168.66.1/24 proto esp spi 0x02000000 reqid 0x02000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.2/24 dst 10.168.66.1/24 

ip netns exec vnet ip xfrm policy add \
    src 10.168.66.1/24 dst 10.168.66.2/24 dir in \
    tmpl src 10.168.66.1/24 dst 10.168.66.2/24 proto esp reqid 0x01000000 mode tunnel

ip netns exec vnet ip xfrm policy add \
    src 10.168.66.2/24 dst 10.168.66.1/24 dir out \
    tmpl src 10.168.66.2/24 dst 10.168.66.1/24 proto esp reqid 0x02000000 mode tunnel



```


```shell
# gre


sudo sysctl -w net.ipv4.ip_forward=1

sudo ip tunnel add gre1 mode gre remote <HOST_B_IP> local <HOST_A_IP> ttl 25

sudo ip addr add <HOST_A_PRIV_IP> dev gre1

sudo ip link set gre1 up

```

# NFTABLES NFT


```shell

# iptables translate, outputs nftables equivalent

iptables-translate -A INPUT -i enp1s0 -p tcp --dport 22 -j ACCEPT

# list

sudo nft list ruleset

# default file at
# /etc/nftools.conf
# or /etc/nftables.conf

# can use include syntax 

include "ipv4-ipv5-webserver-rules.nft"


```


# OPENVSWITCH OVS

```shell

sudo apt update 
sudo apt install build-essential make autoconf libtool
git clone https://github.com/openvswitch/ovs.git

cd ovs 

git switch -c myovs origin/branch-3.6

./boot.sh 

./configure

make 

sudo make install
```

```shell
# create, add
sudo ovs-vsctl add-br ovs-br0

sudo ovs-vsctl add-port ovs-br0 veth11

sudo ovs-vsctl add-port ovs-br0 veth21

sudo ip link set up veth11

sudo ip link set up veth21

sudo ip link set ovs-br0 up

```


# FIREWALL  

```shell


# ubuntu 



sudo ufw default allow incoming 

sudo ufw default allow outgoing 

 

sudo ufw allow ssh 

sudo ufw allow https 

 

sudo ufw allow 22 

sudo ufw allow 443 

 

sudo ufw allow 6000:6007/tcp 

 

sudo ufw allow from 203.0.113.4 to any port 22 

 

sudo ufw allow from 203.0.113.0/24 

 

sudo ufw deny from 203.0.113.4 

 

sudo ufw enable 

 

sudo ufw disable 

 

 

# centos 

 

systemctl enable firewalld 

 

sudo firewall-cmd --permanent --add-service={http,https} --permanent 

 

sudo firewall-cmd --add-port=7070/tcp --permanent 

 

firewall-cmd --zone=trusted --add-source=192.168.0.1/24 --permanent 

 

firewall-cmd --zone=trusted --add-source=10.10.0.0/16 --permanent 

```

# SSH 

```shell
# use identity

# private key at
# ~/.ssh/identity

# .ssh/config

Host 192.168.101.171
  HostName 192.168.101.171
  User thy
  IdentityFile       ~/.ssh/identity

```

# SSH TUNNEL 

```shell

ssh -f user@ssh.server.com -L 2000:ssh.server.com:2005 -N

ssh -f -L 2000:ssh.server.com:2005 user@ssh.server.com -N

```


# SSH KEY DISTRIBUTE

```shell
ssh-keygen -t rsa 

 

ssh-copy-id username@node_name 


# move id_rsa to the client 

# add id_rsa.pub to authrized_keys 

# on client move id_rsa to ~/.ssh 


```

# NCAT

```shell

apt install -y ncat 

 

ncat -lvp <port> 

 

ncat <addr> <port> -e /bin/bash
```


# AP

```shell
sudo apt-get install hostapd dnsmasq

sudo vim /etc/hostapd/hostapd.conf
```

```shell
# /etc/hostapd/hostapd.conf
interface=wlan0
driver=nl80211
ssid=MyWiFiNetwork
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=12345678
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```

```shell
sudo vim /etc/default/hostapd
```

```shell
# /etc/default/hostapd

DAEMON_CONF="/etc/hostapd/hostapd.conf"
```

```shell

sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl start hostapd


sudo cp /etc/dnsmasq.conf /etc/dnsmasq.conf.org

sudo vim /etc/dnsmasq.conf

```

```shell
# /etc/dnsmasq.conf
port=5353
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
```
```shell

sudo systemctl enable hostapd
sudo systemctl start hostapd
sudo systemctl reload dnsmasq

sudo vim /lib/systemd/system/dnsmasq.service
```

```shell
# /lib/systemd/system/dnsmasq.service

After=network-online.target
Wants=network-online.target
```

```shell
sudo vim /etc/netplan/50-cloud-init.yaml
```

```yaml
network:
    ethernets:
        eth0:
            dhcp4: true
            optional: true
        wlan0:
            dhcp4: false
            addresses:
            - 192.168.4.1/24
    version: 2
```

```shell
sudo reboot

# to internet

# file
sudo nano /etc/sysctl.d/routed-ap.conf
# or
sudo nano /etc/sysctl.conf

# Enable IPv4 routing
net.ipv4.ip_forward=1
# instant enabling
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# save using command
sudo netfilter-persistent save
# or
sudo bash -c "iptables-save > /etc/iptables.ipv4.nat"

sudo nano /etc/rc.local
# add above exit0
iptables-restore < /etc/iptables.ipv4.nat

# or simply with iptables-save

sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6



sudo reboot


```

# DHCP SERVER

```shell
sudo apt install isc-dhcp-server

```

```shell
# interface

sudo vim /etc/default/isc-dhcp-server
----
INTERFACESv4="enp0s8"
----


# /etc/dhcp/dhcpd.conf

# comment if not using dns server

#option domain-name "example.org";
#option domain-name-servers ns1.example.org, ns2.example.org;

# uncomment if the official dhcp server for the local network
authoritative;
# define subnet per interface

subnet 10.1.1.0 netmask 255.255.255.0 {
  range 10.1.1.3 10.1.1.254;
}

subnet 192.168.0.0 netmask 255.255.0.0 {
}
```

```shell


# /etc/dhcp/dhcpd.conf

default-lease-time 600;
max-lease-time 7200;

# define dns server


subnet 10.1.1.0 netmask 255.255.255.0 {
  range 10.1.1.3 10.1.1.254;
  option domain-name-servers 10.1.1.1, 8.8.8.8;
}

subnet 192.168.0.0 netmask 255.255.0.0 {
}

# define default gateway

subnet 10.1.1.0 netmask 255.255.255.0 {
  range 10.1.1.3 10.1.1.254;
  option routers 10.1.1.1;
}


# define static ip
host web-server {
  hardware ethernet 00:17:a4:c2:44:22;
  fixed-address 10.1.1.200;
}

```

```shell
sudo systemctl enable isc-dhcp-server
sudo systemctl start isc-dhcp-server
```

```shell

# to internet

# file
sudo nano /etc/sysctl.d/routed-ap.conf
# or
sudo nano /etc/sysctl.conf

# Enable IPv4 routing
net.ipv4.ip_forward=1
# instant enabling
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE

# save using command
sudo netfilter-persistent save
# or
sudo bash -c "iptables-save > /etc/iptables.ipv4.nat"

sudo nano /etc/rc.local
# add above exit0
iptables-restore < /etc/iptables.ipv4.nat

# or simply with iptables-save

sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6



sudo reboot

```

# DNS SERVER

```shell

sudo apt-get install bind9

# /etc/default/bind9

# ipv4
OPTIONS="-4 -u bind"

# ipv6
OPTIONS="-6 -u bind"

# /etc/bind/named.conf.options

acl "trusted" {
        192.168.50.43;    # ns1 - can be set to localhost
        192.168.50.44;    # ns2
        192.168.50.24;  # host1
        192.168.50.25;  # host2
};

...

options {
        directory "/var/cache/bind";
        recursion yes;                 # enables resursive queries
        allow-recursion { trusted; };  # allows recursive queries from "trusted" clients
        listen-on { 192.168.50.43; };   # ns1 private IP address - listen on private network only
        allow-transfer { none; };      # disable zone transfers by default

        forwarders {
                8.8.8.8;
                8.8.4.4;
        };
};


# /etc/bind/named.conf.local

# forward
zone "hey.example.com" {
    type master;
    file "/etc/bind/zones/db.hey.example.com"; # zone file path
    allow-transfer { 192.168.50.44; };         # ns2 private IP address - secondary
};

# reverse

zone "50.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.192.168.50";  # 192.168.50.0/24 subnet
    allow-transfer { 192.168.50.44; };  # ns2 private IP address - secondary
};



sudo mkdir /etc/bind/zones

# forward zone
cd /etc/bind/zones
sudo cp ../db.local ./db.hey.example.com


sudo vim db.hey.example.com

# replace SOA first to ns1 FQDN
# replace SOA second to admin.${domain}
# increase serial by 1

@       IN      SOA     ns1.hey.example.com. admin.hey.example.com. (
                              3         ; Serial

# delete NS, A, AAA

# add NS

; name servers - NS records
    IN      NS      ns1.hey.example.com.
    IN      NS      ns2.hey.example.com.

# add A

; name servers - A records
ns1.hey.example.com.          IN      A       192.168.50.43
ns2.hey.example.com.          IN      A       192.168.50.44

; 10.128.0.0/16 - A records
host1.hey.example.com.        IN      A      192.168.50.24
host2.hey.example.com.        IN      A      192.168.50.25



# reverse zone
cd /etc/bind/zones
sudo cp ../db.127 ./db.192.168.50

# do the same as forward with SOA
# but here match the serial with the forward
@       IN      SOA     ns1.hey.example.com. admin.hey.example.com. (
                              3         ; Serial

# delete NS, PTR

# add NS

; name servers - NS records
      IN      NS      ns1.hey.example.com.
      IN      NS      ns2.hey.example.com.

# add PTR
# add PTR records for all of your servers whose IP addresses are on the subnet of the zone file that you are editing

; PTR Records
43   IN      PTR     ns1.hey.example.com.    ; 192.168.50.43
44   IN      PTR     ns2.hey.example.com.    ; 192.168.50.44
24   IN      PTR     host1.hey.example.com.  ; 192.168.50.24
25   IN      PTR     host2.hey.example.com.  ; 192.168.50.25

# subnet /16 example
#; PTR Records
#11.10   IN      PTR     ns1.nyc3.example.com.    ; 10.128.10.11
#12.20   IN      PTR     ns2.nyc3.example.com.    ; 10.128.20.12
#101.100 IN      PTR     host1.nyc3.example.com.  ; 10.128.100.101
#102.200 IN      PTR     host2.nyc3.example.com.  ; 10.128.200.102


# configuration check

sudo named-checkconf

# zone file check

sudo named-checkzone

# forward zone check

sudo named-checkzone hey.example.com db.hey.example.com

# reverse zone check

sudo named-checkzone 50.168.192.in-addr.arpa /etc/bind/zones/db.192.168.50


# restart to apply

sudo systemctl restart bind9



# dns client

sudo apt install resolvconf

sudo vim /etc/resolvconf/resolv.conf.d/head

search hey.example.com  # your private domain
nameserver 192.168.50.43  # ns1 private IP address
nameserver 192.168.50.44  # ns2 private IP address

# regen /etc/resolv.conf

sudo resolvconf -u

# or you can use netplan, interface, ip ...


# forward lookup

nslookup host1.hey.example.com

# reverse lookup

nslookup 192.168.50.24


# adding new

# Forward zone file: Add an “A” record for the new host, increment the value of “Serial”
# Reverse zone file: Add a “PTR” record for the new host, increment the value of “Serial”
# Add your new host’s private IP address to the “trusted” ACL (named.conf.options)


# adding ns2


# same /etc/bind/named.conf.options but change listen-on

# /etc/bind/named.conf.local

zone "hey.example.com" {
    type slave;
    file "slaves/db.hey.example.com";
    masters { 192.168.50.43; };  # ns1 private IP
};

zone "50.168.192.in-addr.arpa" {
    type slave;
    file "slaves/db.192.168.50";
    masters { 192.168.50.43; };  # ns1 private IP
};

# adding new on slave

# Add your new host’s private IP address to the “trusted” ACL (named.conf.options)



```

# BGP BIRD

```shell

sudo apt update
sudo apt install bird

# on machine1
# /etc/bird/bird.conf 

router id 10.168.0.29;

protocol kernel {
  metric 0;
  import none;
  learn;
  export all;
}

protocol device {
}

protocol direct {
}

protocol bgp peer2 {
  local as 64512;
  neighbor 10.168.0.26 as 64513;
  import all;
  export all;
}

# on machine2
# /etc/bird/bird.conf

router id 10.168.0.26;


protocol kernel {
  metric 0;
  import none;
  learn;
  export all;

}

protocol device {
}

protocol direct {
}

protocol bgp peer1 {
  local as 64513;
  neighbor 10.168.0.29 as 64512;
  import all;
  export all;
}

# check 

birdc show protocols 

birdc show protocols all peer2

birdc show route



```



# FS MOUNT

```shell


lsblk 

 

mkfs.<fs> <drive> 2>/dev/null 

 

mkfs.xfs /dev/sdb 2>/dev/null 

 

mkdir <dir> 

 

mount <drive> <dir> 

 

df 

 

/etc/fstab 

```


# RAID

```shell


mdadm --create --verbose /dev/md0 --level=1 --raid-devices=2 /dev/sdb /dev/sdc  

 

mkfs.<fs> <drive> 2>/dev/null 

 

mkdir <dir> 

 

mount <drive> <dir> 

 

df 

 

/etc/fstab 

```

# LVM DISK EXTENSION

```shell

# resize 

 

sudo lvremove /dev/ubuntu-box-SOMETHING 

 

sudo lvm lvextend -l +100%FREE /dev/ubuntu-box-1-vg 

 

sudo resize2fs -p /dev/ubuntu-box-1-vg 

 

# xfs 

sudo xfs_growfs /dev/ubuntu-box-1-vg 

 

# extend 

 

sudo pvcreate /dev/vdb 

 

sudo vgextend ubuntu-box-1-vg /dev/vdb 

 

sudo lvm lvextend -l +100%FREE /dev/ubuntu-box-1-vg 

 

sudo resize2fs -p /dev/ubuntu-box-1-vg 

 

# xfs 

sudo xfs_growfs /dev/ubuntu-box-1-vg 

 

/etc/fstab 

```
# RSYNC

```shell
rsync -chavzP --stats user@remote.host:/path/to/copy /path/to/local/storage
```

# NFS

```shell


# on nfs server 

 

sudo apt install nfs-kernel-server 

 

sudo apt install nfs-common 

 

mkdir -p /nfs/data 

 

sudo chown nobody:nogroup /nfs/data 

 

sudo vim /etc/exports   


```

```shell
# /etc/exports   


... 

/nfs/data    <client-addr>(rw,sync,no_subtree_check)  

 

```

```shell

exportfs -a 

 

sudo systemctl restart nfs-kernel-server  

 

# on nfs client 

 

sudo apt install nfs-common 

 

mkdir -p /nfsclient/upload 

 

sudo mount <nfs-server-addr>:/nfs/data /nfsclient/upload 

 

# disconnect  

 

sudo umount /nfsclient/upload 

 


```



# CHECK FILE SYSTEM FS INTEGRITY

```shell
fsck

```

# DD FORMAT DISK FDISK

```shell
# check disk

fdisk -l


# unmount

umount /dev/sdb


# format
sudo dd if=/dev/zero of=/dev/sdb bs=1m

# create new partition

fdisk
n

# write save

fdisk
w

# format iso on usb

sudo dd bs=4M if=filename.iso of=/dev/sdb status=progress

# format fs

sudo mkfs.vfat /dev/sdb1 

# eject

sudo eject /dev/sdb
```

# APT

```shell

# hash sum mismatch

sudo rm -rf /var/lib/apt/lists/*

sudo apt clean

sudo apt update


```

# APT KEY

```shell

# apt-key 

 

sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys <> 

 

# wget or curl 

 

sudo wget -q -O /usr/share/keyrings/<>.gpg https://<>/<>.gpg 

 

echo "deb [signed-by=/usr/share/keyrings/<>.gpg] https://packages.cloud.google.com/apt kubernetes-xenial" | sudo tee -a /etc/apt/sources.list.d/cloud-google.list 

 

```

# GOLANG

```shell
curl -OL https://golang.org/dl/go1.16.7.linux-amd64.tar.gz 

 

sudo tar -C /usr/local -xvf go1.16.7.linux-amd64.tar.gz 

 

sudo nano ~/.profile 


```

```shell
. . . 

export PATH=$PATH:/usr/local/go/bin 
```

```shell
source ~/.profile 

```

```shell

# private module

# $HOME/.gitconfig

[url "https://${ID}:${PW}@private.git.com"]
        insteadOf = https://private.git.com

# or

git config --global url."https://${ID}:${PW}@private.git.com".insteadOf "https://private.git.com"

export GONOPROXY=private.git.com
export GONOSUMDB=private.git.com
export GOPRIVATE=private.git.com

# subgroup

git config --global url."https://${ID}:${PW}@private.git.com/sub".insteadOf "https://private.git.com/sub"

export GONOPROXY=private.git.com/sub
export GONOSUMDB=private.git.com/sub
export GOPRIVATE=private.git.com/sub

```


# CRYPTO

```shell

openssl


# issuer(ca) keygen

openssl genrsa -out ca_priv.pem 2048

openssl rsa -in ca_priv.pem -outform PEM -pubout -out ca_pub.pem

# ec 

openssl genpkey -algorithm ed25519 -out ./certs/ca_priv.pem 

openssl pkey -in ./certs/ca_priv.pem -outform PEM -pubout -out ./certs/ca_pub.pem

# gencert

openssl req -x509 -new -key ca_priv.pem -days 365 -out ca.crt -subj "/CN=issuerforseantywork.com"


# subject(issuer) keygen

openssl genrsa -out sub_priv.pem 2048

openssl rsa -in sub_priv.pem -outform PEM -pubout -out sub_pub.pem

# ec

openssl genpkey -algorithm ed25519 -out ./certs/server.key 

openssl pkey -in ./certs/server.key -outform PEM -pubout -out ./certs/server.pub



# subject csr

openssl req -key sub_priv.pem -new -sha256 -out sub.csr -subj "/CN=subjectforseantywork.com"

# issuer signing

openssl  x509 -req -days 180 -in sub.csr -CA ca.crt -CAkey ca_priv.pem -CAcreateserial -sha256 -out sub.crt

# issuer signing with sans

openssl  x509 -req -extfile <(printf "subjectAltName = DNS:some.thing") -days 180 -in sub.csr -CA ca.crt -CAkey ca_priv.pem -CAcreateserial -sha256 -out sub.crt

# read csr, certificate

openssl x509 -in <csr,crt> -text -noout

# verify subject cert against issuer cert

openssl verify -CAfile ca.crt sub.crt


# ca extension


CONFIG="[ v3_req ]\n" && \
CONFIG="${CONFIG}subjectKeyIdentifier=hash\n" && \
CONFIG="${CONFIG}authorityKeyIdentifier=keyid:always,issuer\n" && \
CONFIG="${CONFIG}basicConstraints=CA:TRUE\n" && \
CONFIG="${CONFIG}keyUsage=keyCertSign,cRLSign\n" && \
openssl req -new -x509 -days 3650 \
	-sha256 -key root.key \
	-out root.crt \
	-subj "/CN=ROOT CA" \
	-config <(printf "${CONFIG}") \
	-extensions v3_req 


# cert extension

EXTFILE="subjectKeyIdentifier=hash\n" && \
EXTFILE="${EXTFILE}authorityKeyIdentifier=keyid,issuer\n" && \
EXTFILE="${EXTFILE}basicConstraints=CA:FALSE\n" && \
EXTFILE="${EXTFILE}subjectAltName=email:copy\n" && \
EXTFILE="${EXTFILE}extendedKeyUsage=serverAuth\n" && \
openssl  x509 -req -days 365 \
	-in ./server.csr \
	-extfile <(printf "${EXTFILE}") \
	-CA ./root.crt \
	-CAkey ./root.key \
  -sha256 \
	-out ./server.crt 



# x509

 certificate and public key send, root ca on the authenticate requester side, chained authentication

 if done, use the pub key to send symmetric key

# gpg

gpg --output encrypted.data --symmetric --cipher-algo AES256 un_encrypted.data

gpg --output un_encrypted.data --decrypt encrypted.data


# john

./john --format=raw-MD5-opencl --wordlist=../passwords.txt --rules ../md5.txt

# hashcat

./hashcat.bin -m 17400 ../sha3_256.txt ../passwords.txt -r ../password_rule.rule -w 3 --force




# quantum safe

# get suitable openssl

OSSLV="openssl-3.4.1"


curl -L "https://github.com/openssl/openssl/releases/download/openssl-$OSSLV/openssl-$OSSLV.tar.gz" -o "openssl-$OSSLV.tar.gz"

tar -zxf "openssl-$OSSLV.tar.gz"

cd "openssl-$OSSLV"

./config

make

make test

sudo make install

sudo ldconfig /usr/local/lib64/

# get oqs

LIBOQSV="0.12.0"
OQSPROVV="0.8.0"

rm -rf liboqs* oqs-provider* *.tar.gz

sudo apt update 

sudo apt install astyle cmake gcc ninja-build python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

curl -L https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$LIBOQSV.tar.gz -o $LIBOQSV.tar.gz


curl -L https://github.com/open-quantum-safe/oqs-provider/archive/refs/tags/$OQSPROVV.tar.gz -o $OQSPROVV.tar.gz


tar xzf $LIBOQSV.tar.gz

tar xzf $OQSPROVV.tar.gz

mv "liboqs-$LIBOQSV" liboqs

mv "oqs-provider-$OQSPROVV" oqs-provider

pushd liboqs

mkdir build 

pushd build 

cmake -GNinja .. 

ninja 

sudo ninja install

popd 

popd 

pushd oqs-provider

cmake -S . -B _build && cmake --build _build && ctest --test-dir _build && sudo cmake --install _build

popd

# add below to /usr/local/ssl/openssl.cnf

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
oqsprovider = oqsprovider_sect
default = default_sect
fips = fips_sect

[default_sect]
activate = 1

[fips_sect]
activate = 1

[oqsprovider_sect]
activate = 1


# check

openssl list -providers



# pq certgen

openssl req -x509 -new -newkey dilithium3 -keyout dilithium3_CA.key -out dilithium3_CA.crt -nodes -subj "/CN=test CA" -days 365

openssl genpkey -algorithm dilithium3 -out dilithium3_srv.key

openssl req -new -newkey dilithium3 -keyout dilithium3_srv.key -out dilithium3_srv.csr -nodes -subj "/CN=test server" 

openssl x509 -req -in dilithium3_srv.csr -out dilithium3_srv.crt -CA dilithium3_CA.crt -CAkey dilithium3_CA.key -CAcreateserial -days 365


# server test

openssl s_server -port 9999 -cert dilithium3_srv.crt -key dilithium3_srv.key -tls1_3 -groups frodo640shake

# client test 

openssl s_client -connect 192.168.64.6:9999 -CAfile certs/dilithium3_ca.crt -groups frodo640shake
```



# CONTAINER PODMAN

```shell

sudo apt-get install -y podman

sudo apt-get install -y podman-compose

# /etc/containers/registries.conf

unqualified-search-registries = ["docker.io"]


```


# CONTAINER DOCKER PRIVATE

```shell

docker login <address:port> 
```


# CONTAINER DOCKER 

```shell


# in case of podman


vim ~/.config/containers/registries.conf

unqualified-search-registries = ["docker.io"]


# login

docker login

# logout 

docker logout

# pull 

docker pull image:tag

# tag 

docker tag orgimg/test newimg/test 

# push 

docker push newimg/test

# build 

docker build -t image-name:tag .

# export 

docker save localhost/image-name:latest -o test.tar.gz

# import 

docker load -i test.tar.gz

# util

docker image ...
docker container ...
docker network ...
docker volume ... 

# network

docker network create --driver=bridge cbr0

# network ls

docker network ls

# network rm 

docker network rm cbr0

# run with name

docker run --rm --name name0  -p 8080:80 localhost/image-name

# run with network

docker run --rm --network cbr0  -p 8080:80 localhost/image-name

# run with port

docker run --rm -p 8080:80 localhost/image-name

# run with volume

docker run --rm -v ./local:/workspace localhost/image-name

# run detached

docker run --rm -d localhost/image-name

# run with command

docker run --rm -t -v ./local:/usr/workspace localhost/image-name /bin/bash -c 'cd test && ./hello.sh'

# run with interactive 

docker run --rm -it -v ./local:/usr/workspace localhost/image-name /bin/bash -c 'cd test && ./hello.sh'

# run with environment 

docker run --rm -e MYENV=hello localhost/image-name


# exec

docker exec -it container /bin/bash

# stop 

docker stop container

```


# VIRTUAL MACHINE QEMU

```shell
sudo apt install qemu-kvm virt-manager virtinst libvirt-clients bridge-utils libvirt-daemon-system -y

sudo systemctl enable --now libvirtd

sudo systemctl start libvirtd

sudo usermod -aG kvm $USER

sudo usermod -aG libvirt $USER

sudo virt-manager

# aarch64 on x64

# adding to the above first line

sudo apt-get install qemu-system-arm qemu-efi

# and set arch as aarch64 virt

# then set UEFI to aarch64


```


# VM QEMU

```shell

virsh shutdown <vm>

virsh start <vm>

# create vm

virsh dumpxml guest1 > guest1.xml

# do some needed editing
# delete uuid

# hard new 
virsh define guest1.xml

# or
# soft new

virsh create guest1.xml

# delete

virsh destroy <vm>

virsh undefine <vm>

rm -rf /var/lib/libvirt/images/<vm>.qcow2


# check device

virsh nodedev-list --cap pci

virsh nodedev-dumpxml pci_0000_00_19_0

# add device

virsh attach-device vm_name --file device.xml --config # --config also persistent, --persistent

# remove device


virsh detach-device vm_name device.xml

# clone 

virt-clone --original ubuntu-box1 --auto-clone

# edit

virsh edit guest

# export/import

# on host 1


virsh list --all

virsh shutdown target_guest_machine

virsh dumpxml target_guest_machine > /root/target_guest_machine.xml

# disk location

virsh domblklist target_guest_name

scp /root/target_guest_machine.xml destination_host_ip:/etc/libvirt/qemu

scp /var/lib/libvirt/images/target_guest_name.qcow2 destination_host_ip:/var/lib/libvirt/images/


# on host 2

# specify qcow2 location

virsh define target_guest_machine.xml

virsh start target_guest_machine


# install

virt-install \
-n ubuntu20-gpu \
--description "ubuntu20-gpu" \
--os-type=Linux \
--os-variant=ubuntu20.04 \
--ram=4096 \
--vcpus=4 \
--disk path=/var/lib/libvirt/images/ubuntu20-gpu.qcow2,format=qcow2,bus=virtio,size=32 \
# --graphics none \
--cdrom /home/seantywork/box/ubuntu-20-server.iso \
--network bridge:br0
# --boot uefi

# vm uefi

sudo apt install ovmf

```

```shell
# clone with xml

virsh shutdown "$source_vm"

virsh dumpxml "$source_vm" > "/tmp/$new_vm.xml"

sed -i /uuid/d "/tmp/$new_vm.xml"
sed -i '/mac address/d' "/tmp/$new_vm.xml"

sed -i "s/$source_vm/$new_vm/" "/tmp/$new_vm.xml"

cp /var/lib/libvirt/images/ubuntu22.04.qcow2 /var/lib/libvirt/images/new.qcow2

virsh define "/tmp/$new_vm.xml"

```

# VM QEMU NETWORK BRIDGE

```shell

# /etc/sysctl.d/10-bridge.conf

net.bridge.bridge-nf-call-ip6tables=0
net.bridge.bridge-nf-call-iptables=0
net.bridge.bridge-nf-call-arptables=0

```

```shell


echo "br_netfilter" > /etc/modules-load.d/br_netfilter.conf

reboot

virsh net-destroy default
virsh net-undefine default

# save /etc/netplan/01-network-manager-all.yaml

```

```yaml

# netplan

# /etc/netplan/00-installer-config.yaml 

network:
  ethernets:
    enx44a92c521758:
      dhcp4: false
      dhcp6: false
  bridges:
    br0:
      interfaces: [ enx44a92c521758 ]
      addresses: [192.168.0.32/24]
      gateway4: 192.168.0.1
      mtu: 1500
      nameservers:
        addresses: [168.126.63.1,8.8.8.8]
      parameters:
        stp: true
        forward-delay: 4
      dhcp4: no
      dhcp6: no
  version: 2


```

```shell
#sudo netplan generate
sudo netplan apply


```

```shell

# network/interfaces
# /etc/network/interfaces

# The primary network interface
auto eno1

#make sure we don't get addresses on our raw device
iface eno1 inet manual
iface eno1 inet6 manual

#set up bridge and give it a static ip
auto br0
allow-hotplug eno1
iface br0 inet static
        address 192.168.0.100
        netmask 255.255.255.0
        network 192.168.0.0
        broadcast 192.168.0.255
        gateway 192.168.0.1
        bridge_ports eno1
        bridge_stp off
        bridge_fd 0
        bridge_maxwait 0
        dns-nameservers 8.8.8.8

#allow autoconf for ipv6
iface br0 inet6 auto
        accept_ra 1



```

```shell

sudo systemctl restart networking

```

```shell
# host-bridge.xml

<network>
    <name>host-bridge</name>
    <bridge name='br0'/>
    <forward mode="bridge"/>
</network>

```

```shell

virsh net-define host-bridge.xml
virsh net-autostart host-bridge
virsh net-start host-bridge
virsh net-list --all

```

# VM QEMU GPU PASSTHROUGH

```shell

# v
# locations
# /etc/default/grub
# /etc/modules
# /etc/modprobe.d/vfio.conf
# /etc/modprobe.d/iommu_unsafe_interrupts.conf
# /etc/modprobe.d/kvm.conf
# /etc/modprobe.d/blacklist.conf

efibootmgr

# vt-x & vt-d enabled

# or amd-v & amd-iommu

# grub iommu config

# v (worked set)
/etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="quiet intel_iommu=on iommu=pt"

# or 

GRUB_CMDLINE_LINUX_DEFAULT="quiet intel_iommu=on iommu=pt vfio-pci.ids=<I:D>,<I:D>"

# or (overkill, explicit)

GRUB_CMDLINE_LINUX_DEFAULT="quiet intel_iommu=on iommu=pt vfio-pci.ids=<I:D>,<I:D> nofb nomodeset initcall_blacklist=sysfb_init video=vesafb:off video=efifb:off video=simplefb:off"

# or (overkill, explicit, unsafe)

GRUB_CMDLINE_LINUX_DEFAULT="quiet intel_iommu=on iommu=pt vfio-pci.ids=<I:D>,<I:D> pcie_acs_override=downstream,multifunction nofb nomodeset initcall_blacklist=sysfb_init video=vesafb:off video=efifb:off video=simplefb:off"


update-grub

reboot

dmesg | grep -e IOMMU

# vfio config
# v
echo "vfio" >> /etc/modules
echo "vfio_iommu_type1" >> /etc/modules
echo "vfio_pci" >> /etc/modules
echo "vfio_virqfd" >> /etc/modules
echo "vfio_nvidia" >> /etc/modules

update-initramfs -u -k all

systemctl reboot

dmesg | grep -i vfio

dmesg | grep 'remapping'

# in case of no remapping
# v
echo "options vfio_iommu_type1 allow_unsafe_interrupts=1" > /etc/modprobe.d/iommu_unsafe_interrupts.conf


# nvidia stability
# v
echo "options kvm ignore_msrs=1 report_ignored_msrs=0" > /etc/modprobe.d/kvm.conf

# amd stability

apt install pve-headers-$(uname -r)
apt install git dkms build-essential
git clone https://github.com/gnif/vendor-reset.git
cd vendor-reset
dkms install .
echo "vendor-reset" >> /etc/modules
update-initramfs -u
shutdown -r now

lspci -nn | grep 'AMD'  # <DEVICE_ID> ex) 01:00.0

cat << EOF >>  /etc/systemd/system/vreset.service
[Unit]
Description=AMD GPU reset method to 'device_specific'
After=multi-user.target
[Service]
ExecStart=/usr/bin/bash -c 'echo device_specific > /sys/bus/pci/devices/0000:<DEVICE_ID>/reset_method'
[Install]
WantedBy=multi-user.target
EOF
systemctl enable vreset.service && systemctl start vreset.service


# gpu isolation and drivers

lspci -nn | grep 'NVIDIA' # or 'AMD'


#v
echo "options vfio-pci ids=<ID>,<ID2>,..." > /etc/modprobe.d/vfio.conf


ex)

echo "options vfio-pci ids=1002:67df,1002:aaf0" > /etc/modprobe.d/vfio.conf

# softdep
# v
echo "softdep snd_hda_intel pre: vfio-pci" >> /etc/modprobe.d/vfio.conf
echo "softdep xhci_hcd pre: vfio-pci" >> /etc/modprobe.d/vfio.conf
echo "softdep xhci_pci pre: vfio-pci" >> /etc/modprobe.d/vfio.conf
echo "softdep nvidia-gpu pre: vfio-pci" >> /etc/modprobe.d/vfio.conf
echo "softdep i2c_nvidia_gpu pre: vfio-pci" >> /etc/modprobe.d/vfio.conf

# blacklist

# AMD drivers
echo "blacklist radeon" >> /etc/modprobe.d/blacklist.conf
echo "blacklist amdgpu" >> /etc/modprobe.d/blacklist.conf
# NVIDIA drivers
# if snd_hda_intel present
# echo "blacklist snd_hda_intel" >> /etc/modprobe.d/blacklist.conf
# v
echo "blacklist nouveau" >> /etc/modprobe.d/blacklist.conf
echo "blacklist nvidia" >> /etc/modprobe.d/blacklist.conf
echo "blacklist nvidiafb" >> /etc/modprobe.d/blacklist.conf
echo "blacklist nvidia_drm" >> /etc/modprobe.d/blacklist.conf
# Intel drivers
echo "blacklist snd_hda_intel" >> /etc/modprobe.d/blacklist.conf
echo "blacklist snd_hda_codec_hdmi" >> /etc/modprobe.d/blacklist.conf
echo "blacklist i915" >> /etc/modprobe.d/blacklist.conf




# gpu in vm

#v
# bios ovmf (uefi)

# machine q35

# display vmware compatible (proxmox)
# or
# v
# video QXL and Display Spice Listen type Address (qemu/kvm)

# add all pci devices within iommu group

# edit if necessary

# (qemu/kvm)

virsh edit vm-gpu

  <features>
    <acpi/>
    <apic/>
    <hyperv>
      <vendor_id state="on" value="whatever"/>
    </hyperv>
    <kvm>
      <hidden state='on'/>
    </kvm>
    <vmport state='off'/>
    <ioapic driver='kvm'/>
  </features>

# boot vm without secure boot (esc || f2)

# check

lspci -nn

# noveau blacklist

sudo nano /etc/modprobe.d/blacklist-nouveau.conf

blacklist nouveau
options nouveau modeset=0

sudo update-initramfs -u


# install corresponding gpu drivers

https://docs.nvidia.com/datacenter/tesla/tesla-installation-notes/index.html

# or 

https://www.nvidia.com/download/index.aspx

# gpu reset at reboot
# if necessary

```

```shell
# /root/reset_pci_gpu.sh
#!/bin/bash
echo 1 > /sys/bus/pci/devices/0000\:09\:00.0/remove
echo 1 > /sys/bus/pci/rescan

crontab -e

@reboot /root/reset_pci_gpu.sh

```

```shell
# gpu reset method disable 
# if necessary

echo > /sys/bus/pci/devices/0000\:09\:00.0/reset_method

```

# VM CLUSTER

```shell

# proxmox


# export/import

qm list

vzdump <id> --compress gzip --storage local

# usually /var/lib/vz/dump

qmrestore /var/lib/vz/dump/vzdump-qemu-<id>.vma.gz <new-id>



# from different

create vm

import vm

import disk

qm importdisk <VM_ID> <OVA_DISK.vmdk> <VOL_NAME> -format qcow2

ex) qm importdisk 101 ubuntu20-disk001.vmdk local-lvm -format qcow2

create cluster

join cluster


# delete cluster

systemctl stop pve-cluster corosync

pmxcfs -l

rm /etc/corosync/*

rm /etc/pve/corosync.conf

killall pmxcfs

systemctl start pve-cluster

```

# RADARE2 R2

```shell

git clone https://github.com/radareorg/radare2

cd radare2 ; sys/install.sh

```

```shell

# cmd opts

-L: List of supported IO plugins
-q: Exit after processing commands
-w: Write mode enabled
-i [file]: Interprets a r2 script
-A: Analyze executable at load time (xrefs, etc)
-n: Bare load. Do not load executable info as the entrypoint
-c 'cmds': Run r2 and execute commands (eg: r2 -wqc'wx 3c @ main')
-p [prj]: Creates a project for the file being analyzed (CC add a comment when opening a file as a project)
-: Opens r2 with the malloc plugin that gives a 512 bytes memory area to play with (size can be changed)
	Similar to r2 malloc://512


# basic


; Command chaining: x 3;s+3;pi 3;s+3;pxo 4;
| Pipe with shell commands: pd | less
! Run shell commands: !cat /etc/passwd
!! Escapes to shell, run command and pass output to radare buffer
` Radare commands: wx `!ragg2 -i exec`
~ grep
~! grep -v
~[n] grep by columns afl~[0]
~:n grep by rows afl~:0
.. repeats last commands (same as enter \n)
( Used to define and run macros
$ Used to define alias
$$: Resolves to current address
Offsets (@) are absolute, we can use $$ for relative ones @ $$+4
? Evaluate expression
?$? Help for variables used in expressions
$$: Here
$s: File size
$b: Block size
$l: Opcode length
$j: When $$ is at a jmp, $j is the address where we are going to jump to
$f: Same for jmp fail address
$m: Opcode memory reference (e.g. mov eax,[0x10] => 0x10)
??? Help for ? command
?i Takes input from stdin. Eg ?i username
?? Result from previous operations
?s from to [step]: Generates sequence from to every
?p: Get physical address for given virtual address
?P: Get virtual address for given physical one
?v Show hex value of math expr
?l str: Returns the length of string
@@: Used for iterations

# position
s address: Move cursor to address or symbol
	s-5 (5 bytes backwards)
	s- undo seek
	s+ redo seek

# block size

b size: Change block size

# analyze

aa: Analyze all (fcns + bbs) same that running r2 with -A
ahl <length> <range>: fake opcode length for a range of bytes
ad: Analyze data
	ad@rsp (analyze the stack)

af: Analyze functions
afl: List all functions
	number of functions: afl~?
afi: Returns information about the functions we are currently at
afr: Rename function: structure and flag
afr off: Restore function name set by r2
afn: Rename function
	afn strlen 0x080483f0
af-: Removes metadata generated by the function analysis
af+: Define a function manually given the start address and length
	af+ 0xd6f 403 checker_loop
axt: Returns cross references to (xref to)
axf: Returns cross references from (xref from)

d, f: Function analysis
d, u: Remove metadata generated by function analysis


# info


iI: File info
iz: Strings in data section
izz: Strings in the whole binary
iS: Sections
	iS~w returns writable sections
is: Symbols
	is~FUNC exports
il: Linked libraries
ii: Imports
ie: Entrypoint

i~pic : check if the binary has position-independent-code
i~nx : check if the binary has non-executable stack
i~canary : check if the binary has canaries

# print

psz n @ offset: Print n zero terminated String
px n @ offset: Print hexdump (or just x) of n bytes
pxw n @ offset: Print hexdump of n words
	pxw size@offset  prints hexadecimal words at address
pd n @ offset: Print n opcodes disassembled
pD n @ offset: Print n bytes disassembled
pi n @ offset: Print n instructions disassembled (no address, XREFs, etc. just instructions)
pdf @ offset: Print disassembled function
	pdf~XREF (grep: XREFs)
	pdf~call (grep: calls)
pcp n @ offset: Print n bytes in python string output.
	pcp 0x20@0x8048550
	import struct
	buf = struct.pack ("32B",
	0x55,0x89,0xe5,0x83,0xzz,0xzz,0xzz,0xzz,0xf0,0x00,0x00,
	0x00,0x00,0xc7,0x45,0xf4,0x00,0x00,0x00,0x00,0xeb,0x20,
	0xc7,0x44,0x24,0x04,0x01,0x00,0x00,0x00,0xzz,0xzz)
p8 n @ offset: Print n bytes (8bits) (no hexdump)
pv: Print file contents as IDA bar and shows metadata for each byte (flags , ...)
pt: Interpret data as dates
pf: Print with format
pf.: list all formats
p=: Print entropy ascii graph

# write

wx: Write hex values in current offset
	wx 123456
	wx ff @ 4
wa: Write assembly
	wa jnz 0x400d24
wc: Write cache commit
wv: Writes value doing endian conversion and padding to byte
wo[x]: Write result of operation
	wow 11223344 @102!10
		write looped value from 102 to 102+10
		0x00000066  1122 3344 1122 3344 1122 0000 0000 0000
	wox 0x90
		XOR the current block with 0x90. Equivalent to wox 0x90 $$!$b (write from current position, a whole block)
	wox 67 @4!10
		XOR from offset 4 to 10 with value 67
wf file: Writes the content of the file at the current address or specified offset (ASCII characters only)
wF file: Writes the content of the file at the current address or specified offset
wt file [sz]: Write to file (from current seek, blocksize or sz bytes)
	Eg: Dump ELF files with wt @@ hit0* (after searching for ELF headers: \x7fELF)
wopO 41424344 : get the index in the De Bruijn Pattern of the given word

# flags

f: List flags
f label @ offset: Define a flag `label` at offset
	f str.pass_len @ 0x804999c
f-label: Removes flag
fr: Rename flag
fd: Returns position from nearest flag (looking backwards). Eg => entry+21
fs: Show all flag spaces
fs flagspace: Change to the specified flag space

# yank & paste

y n: Copies n bytes from current position
y: Shows yank buffer content with address and length where each entry was copied from
yp: Prints yank buffer
yy offset: Paste the contents of the yank buffer at the specified offset
yt n target @ source: Yank to. Copy n bytes from source to target address


# visual mode

q: Exits visual mode
hjkl: move around (or HJKL) (left-down-up-right)
o: go/seek to given offset
?: Help
.: Seek EIP
<enter>: Follow address of the current jump/call
:cmd: Enter radare commands. Eg: x @ esi
d[f?]: Define cursor as a string, data, code, a function, or simply to undefine it.
	dr: Rename a function
	df: Define a function
v: Get into the visual code analysis menu to edit/look closely at the current function.
p/P: Rotate print (visualization) modes
    hex, the hexadecimal view
    disasm, the disassembly listing
		Use numbers in [] to follow jump
		Use "u" to go back
    debug, the debugger
    words, the word-hexidecimal view
    buf, the C-formatted buffer
    annotated, the annotated hexdump.
c: Changes to cursor mode or exits the cursor mode
    select: Shift+[hjkl]
    i: Insert mode
    a: assembly inline
    A: Assembly in visual mode
    y: Copy
    Y: Paste
    f: Creates a flag where cursor points to
    <tab> in the hexdump view to toggle between hex and strings columns
V: View ascii-art basic block graph of current function
W: WebUI
x, X: XREFs to current function. ("u" to go back)
t: track flags (browse symbols, functions..)
gG: Begin or end of file
HUD
	_ Show HUD
	backspace: Exits HUD
	We can add new commands to HUD in: radare2/shlr/hud/main
;[-]cmt: Add/remove comment
m<char>: Define a bookmark
'<char>: Go to previously defined bookmark
'

# rop

/R opcodes: Search opcodes
	/R pop,pop,ret
/Rl opcodes: Search opcodes and print them in linear way
	/Rl jmp eax,call ebx
/a: Search assembly
	/a jmp eax
pda: Returns a library of gadgets that can be use. These gadgets are obtained by disassembling byte per byte instead of obeying to opcode length


# searching

/ bytes: Search bytes
	\x7fELF

# compare files

r2 -m 0xf0000 /etc/fstab	; Open source file
o /etc/issue  				; Open file2 at offset 0
o  							; List both files
cc offset: Diff by columns between current offset address and "offset"

# graphs

af: Load function metadata
ag $$ > a.dot: Dump basic block graph to file
ag $$ | xdot -: Show current function basic block graph


af: Load function metadata
agc $$ > b.dot: Dump basic block graph to file

dot -Tpng -o /tmp/b.png b.dot

radiff2 -g main crackme.bin crackme.bin > /tmp/a
xdot /tmp/a

# debugger

r2 -d [pid|cmd|ptrace] (if command contains spaces use quotes: r2 -d "ls /")

ptrace://pid (debug backend does not notice, only access to mapped memory)

r2 -d rarun2 program=pwn1 arg1=$(python exploit.py)


r2 -d rarun2 program=/bin/ls stdin=$(python exploit.py)

do: Reopen program
dp: Shows debugged process, child processes and threads
dc: Continue
dcu <address or symbol>: Continue until symbol (sets bp in address, continua until bp and remove bp)
dc[sfcp]: Continue until syscall(eg: write), fork, call, program address (To exit a library)
ds: Step in
dso: Step out
dss: Skip instruction
dr register=value: Change register value
dr(=)?: Show register values
db address: Sets a breakpoint at address
	db sym.main add breakpoint into sym.main
	db 0x804800 add breakpoint
	db -0x804800 remove breakpoint
dsi (conditional step): Eg: "dsi eax==3,ecx>0"
dbt: Shows backtrace
drr: Display in colors and words all the refs from registers or memory
dm: Shows memory map (* indicates current section)
	[0xb776c110]> dm
	sys 0x08048000 - 0x08062000 s r-x /usr/bin/ls
	sys 0x08062000 - 0x08064000 s rw- /usr/bin/ls
	sys 0xb776a000 - 0xb776b000 s r-x [vdso]
	sys 0xb776b000 * 0xb778b000 s r-x /usr/lib/ld-2.17.so
	sys 0xb778b000 - 0xb778d000 s rw- /usr/lib/ld-2.17.so
	sys 0xbfe5d000 - 0xbfe7e000 s rw- [stack]


```


# SERIAL SPI I2C UART


```shell

# on rpi4

sudo vim /boot/config.txt


# add or uncomment for i2c
dtparam=i2c_arm=on


# add or uncomment for spi
dtparam=spi=on
dtoverlay=spi1-1cs

# add or uncomment for uart
enable_uart=1

...

arm_boost=1

[all]

# add or uncomment for freq stabilization
force_turbo=1




sudo reboot


```
