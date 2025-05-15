# linuxyz

***crap compilation of mostly Linux stuff***


**Disclaimer : I am not liable for any misuse of this code Only use it on machines and in environments that you have explicit permissions and authrizations to do so**


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
  build-essential
  go
  make
  git
  curl
  docker
  chrome
  libreoffice
  vscode
  virsh
  wireshark
  gh


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

make -j4 deb-pkg

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
efibootmgr
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



# PROFILE PATH PERMANENT

```shell

vim .profile

source .profile

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
 

# NGINX SETTING


```shell
sudo mkdir -pv /var/www/<project_name>/static/ 

sudo chown -cR ubuntu:ubuntu /var/www/<project_name>/  

 

django setting.py debug false 

python manage.py collectstatic 
```

# HTTPS

```shell

# Nginx configuration: /etc/nginx/sites-available/<nginx_config_name> 

server_tokens               off; 

access_log                  /var/log/nginx/<nginx_config_name>.access.log; 

error_log                   /var/log/nginx/<nginx_config_name>.error.log; 

 

server { 

  server_name               .<domain_name>; 

  listen                    80; 

  return                    307 https://$host$request_uri; 

} 

 

server { 

  location / { 

    proxy_pass              http://localhost:8000; 

    proxy_set_header        Host $host; 

    proxy_set_header    X-Forwarded-Proto $scheme; 

  } 

 

  location /static { 

    autoindex on; 

    alias <static_location>; 

  } 

 

  listen 443 ssl; 

  ssl_certificate /etc/letsencrypt/live/www.supersecure.codes/fullchain.pem; 

  ssl_certificate_key /etc/letsencrypt/live/www.supersecure.codes/privkey.pem; 

  include /etc/letsencrypt/options-ssl-nginx.conf; 

  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; 

} 


```

```shell

sudo systemctl restart nginx 

 

cd /etc/nginx/sites-enabled 

sudo ln -s ../sites-available/<nginx_config_name> . 

 

sudo vi /etc/nginx/nginx.conf 

ssl_protocols TLSv1.2 TLSv1.3; 

include /etc/nginx/sites-enabled/<nginx_config_name> 

sudo systemctl restart nginx 

 

sudo snap install --classic certbot 

sudo ln -s /snap/bin/certbot /usr/bin/certbot 

sudo certbot --nginx --rsa-key-size 4096 --no-redirect 

 

sudo systemctl restart nginx 

 


```


# AWS RESTART

```shell
# ip and dns check 

# aws new ssh domain and ip check  

# namecheap DNS relinking 

```


# NGINX CHECK 

```shell



 

stream { 

        upstream galera_cluster { 

            server 127.0.0.1:33061; #node1 

            server 127.0.0.1:33062; #node2 

            server 127.0.0.1:33063; #node3 

            zone tcp_mem 64k; 

            least_conn; 

        } 

 

        server { 

            listen 3306; # MySQL default 

            proxy_pass galera_cluster; 

        } 

} 

 

 

http  

 

        sendfile on; 

        tcp_nopush on; 

        tcp_nodelay on; 

        reset_timedout_connection on; 

        client_body_timeout 3600; 

        send_timeout 2; 

 

        keepalive_timeout 30; 

        keepalive_requests 100000; 

 

        #types_hash_max_size 2048; 

        # server_tokens off; 

 

        client_max_body_size 40G; 

        client_body_buffer_size 16K; 

        client_header_buffer_size 1K; 

 

        proxy_request_buffering off; 

 

        proxy_send_timeout 3600; 

 

server 

 

location 

 

                proxy_pass http://agc_server; 

                proxy_read_timeout 300s; 

                proxy_connect_timeout 75s; 

                proxy_set_header X-Real-IP $remote_addr; 

                #proxy_set_header Host $host; 

                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; 

                proxy_set_header X-Forwarded-For $remote_addr; 

                proxy_set_header X-Forwarded-Proto $scheme; 

                proxy_set_header Host $http_host; 

                proxy_http_version 1.1; 

                proxy_set_header   Upgrade $http_upgrade; 

                proxy_set_header   Connection "upgrade"; 

 

 

```


```shell
# or

upstream UC {

  server 0.0.0.0:8888;

}

upstream PTT {

  server 0.0.0.0:8888;

}


server
{
        listen       80;
        server_name      usagecorpus.com www.usagecorpus.com;
        return 301 https://$host$request_uri;
}

server
{
        listen       80;
        server_name      ptt.usagecorpus.com;
        return 301 https://$host$request_uri;
}



server
{
        server_name  usagecorpus.com www.usagecorpus.com;
        client_max_body_size 0;

        location / {
            # add_header Content-Type text/plain;
            # return 200 'okay';

             proxy_pass http://UC;
             proxy_set_header X-Real-IP $remote_addr;
             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
             proxy_set_header X-Forwarded-For $remote_addr;
             proxy_set_header X-Forwarded-Proto $scheme;
             proxy_set_header Host $http_host;

       #      proxy_buffering off;
       #      proxy_request_buffering off;

       #      proxy_http_version 1.1;
       #      proxy_set_header   Upgrade $http_upgrade;
       #      proxy_set_header   Connection "upgrade";


      }


    #listen 80; # managed by Certbot

    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/usagecorpus.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/usagecorpus.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot


}

server
{
        server_name  ptt.usagecorpus.com;
        client_max_body_size 0;

        location / {
            # add_header Content-Type text/plain;
            # return 200 'okay';

             proxy_pass http://PTT;
             proxy_set_header X-Real-IP $remote_addr;
             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
             proxy_set_header X-Forwarded-For $remote_addr;
             proxy_set_header X-Forwarded-Proto $scheme;
             proxy_set_header Host $http_host;

       #      proxy_buffering off;
       #      proxy_request_buffering off;

       #      proxy_http_version 1.1;
       #      proxy_set_header   Upgrade $http_upgrade;
       #      proxy_set_header   Connection "upgrade";


       }


    #listen 80; # managed by Certbot

    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/usagecorpus.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/usagecorpus.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

}

```

```shell
sudo systemctl start nginx 

sudo systemctl restart nginx 

 

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

sudo iptables -t nat -A POSTROUTING -o wlo1 -p tcp -s 192.168.10.50 -j SNAT 192.168.10.5


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

sudo ip route add 192.168.64.0/24 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.64.1 dev veth4

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1


sudo ip netns exec net1 ip link add br0 type bridge stp_state 0

sudo ip netns exec net1 ip link set veth2 master br0 

sudo ip netns exec net1 ip link set veth3 master br0

sudo ip netns exec net1 ip addr add 10.168.100.1/24 dev br0

sudo ip netns exec net1 ip link set br0 up

sudo ip netns exec net1 ip link set veth2 up 

sudo ip netns exec net1 ip link set veth3 up

sudo ip netns exec net1 ip route add default via 10.168.100.1 dev br0

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

ip link add bond1 type bond miimon 100 mode active-backup
ip link set eth0 master bond1
ip link set eth1 master bond1
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

# CONNTRACK


```shell

sudo apt-get install conntrack


sudo conntrack -L

# delete
conntrack -D -p tcp --dport 993

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



# GRPC

```shell
# golang

apt install -y protobuf-compiler

apt install golang-goprotobuf-dev -y

go install google.golang.org/protobuf/cmd/protoc-gen-go

go install google.golang.org/grpc/cmd/protoc-gen-go-grpc

export PATH="$PATH:$(go env GOPATH)/bin"

protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    ./chat.proto
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

# SSHFS


```shell

sudo apt install sshfs

# mount local to remote

sshfs -p $PORT /data/local user@host:/data/remote

# unmount 

sudo umount /data/local

# make permanent

sudo nano /etc/fstab


user@host:/data/remote /data/local  fuse.sshfs noauto,x-systemd.automount,_netdev,reconnect,identityfile=/home/sammy/.ssh/id_rsa,allow_other,default_permissions, port=$PORTNUMBER 0 0

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

# DB SYNC REPLICATION

```shell



sudo apt install mysql-server mysql-client 

 

mysql_secure_installation 

 

# dump 

 

mysqldump -u username -p database_name > data-dump.sql 

 

mysql -u username -p new_database < data-dump.sql 

 

# sync 

 

# master 

 

sudo vim /etc/mysql/mysql.conf.d/mysqld.cnf 
```

```shell
bind-address 	 =0.0.0.0 

 

server-id	 =1 

... 

log_bin = /var/log/mysql/mysql-bin.log 

log_bin_index =/var/log/mysql/mysql-bin.log.index 

relay_log = /var/log/mysql/mysql-relay-bin 

relay_log_index = /var/log/mysql/mysql-relay-bin.index 
```

```shell

sudo systemctl restart mysql 

 

sudo mysql -u root -p 

 

CREATE USER 'replication_user'@'*' IDENTIFIED BY 'replica_password'; 

 

GRANT REPLICATION SLAVE ON *.* TO 'replication_user'@'*'; 

 

SHOW MASTER STATUS\G 

 

// Get File (MASTER_LOG_FILE), Position (MASTER_LOG_POS) 


# slave 

 

sudo vim  /etc/mysql/mysql.conf.d/mysqld.cnf 
```

```shell
# /etc/mysql/mysql.conf.d/mysqld.cnf 

bind-address           = 0.0.0.0 

 

server-id		=2  

 

log_bin = /var/log/mysql/mysql-bin.log 

log_bin_index =/var/log/mysql/mysql-bin.log.index 

relay_log = /var/log/mysql/mysql-relay-bin 

relay_log_index = /var/log/mysql/mysql-relay-bin.index 


```

```shell
 

sudo mysql -u root -p 

 

STOP SLAVE;  

 

CHANGE MASTER TO MASTER_HOST ='MASTER_IP', MASTER_USER ='replication_user', MASTER_PASSWORD ='replica_password', MASTER_LOG_FILE = 'mysql-bin.000002', MASTER_LOG_POS = 1643; 

 

START SLAVE; 

 

# MGR 

 

uuidgen 

 

sudo vim  /etc/mysql/mysql.conf.d/mysqld.cnf 

```

```shell

[mysqld] 

 

# General replication settings 

disabled_storage_engines="MyISAM,BLACKHOLE,FEDERATED,ARCHIVE,MEMORY" 

gtid_mode = ON 

enforce_gtid_consistency = ON 

master_info_repository = TABLE 

relay_log_info_repository = TABLE 

binlog_checksum = NONE 

log_slave_updates = ON 

log_bin = binlog 

binlog_format = ROW 

transaction_write_set_extraction = XXHASH64 

loose-group_replication_bootstrap_group = OFF 

loose-group_replication_start_on_boot = OFF 

loose-group_replication_ssl_mode = REQUIRED 

loose-group_replication_recovery_use_ssl = 1 

 

# Shared replication group configuration 

loose-group_replication_group_name = "" # uuidgen value 

loose-group_replication_ip_whitelist = "ip1,ip2,ip3" # group ips 

loose-group_replication_group_seeds = "ip1:port,ip2:port,ip3:port" # group ips with ports # port usually 33061 

 

# Single or Multi-primary mode? Uncomment these two lines 

# for multi-primary mode, where any host can accept writes 

#loose-group_replication_single_primary_mode = OFF  # for multi primary group uncomment 

#loose-group_replication_enforce_update_everywhere_checks = ON # for multi primary group uncomment 

 

# Host specific replication configuration 

server_id =    # id 

bind-address = "" # bind-address 

report_host = "" # bind-address  

loose-group_replication_local_address = "" # bind-address:port # port usually 33061 


```

```shell


systemctl restart mysql 

 

# on all members 

 

mysql 

 

SET SQL_LOG_BIN=0; 

 

CREATE USER 'repl'@'%' IDENTIFIED BY 'password' REQUIRE SSL; 

 

GRANT REPLICATION SLAVE ON *.* TO 'repl'@'%'; 

 

FLUSH PRIVILEGES; 

 

SET SQL_LOG_BIN=1; 

 

CHANGE REPLICATION SOURCE TO SOURCE_USER='repl', SOURCE_PASSWORD='password' FOR CHANNEL 'group_replication_recovery'; 

# or 

CHANGE MASTER TO MASTER_USER='repl', MASTER_PASSWORD='password' FOR CHANNEL 'group_replication_recovery'; 

 

INSTALL PLUGIN group_replication SONAME 'group_replication.so'; 

 

# on one member (maybe first) 

 

SET GLOBAL group_replication_bootstrap_group=ON; 

 

START GROUP_REPLICATION; 

 

SET GLOBAL group_replication_bootstrap_group=OFF; 

 

# on the other members 

 

START GROUP_REPLICATION; 

 

 
```

# MONGODB

```shell

curl -fsSL https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add - 

 

echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list 

 

sudo apt update 

 

sudo apt install mongodb-org 

 

mkdir -p ~/data/db 

 

sudo mongod --dbpath ~/data/db 


```


# CHROME

```shell

# download .deb 

 

sudo apt install ./<file>.deb 


```


# VSCODE

```shell
# download .deb 

 

sudo apt install ./<file>.deb 
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

# JMETER

```shell

# install openjdk

# create thread group

# add sampler

jmeter -n -t <ThreadGroup.jmx> -l <report.csv> -e -o <report>

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

openssl s_server -cert dilithium3_srv.crt -key dilithium3_srv.key -www -tls1_3 -groups frodo640shake

# client test 

openssl s_client -groups frodo640shake -CAfile certs/dilithium3_ca.crt 
```



# DOCKER INSTALL

```shell


apt remove docker docker-engine docker.io containerd runc 

apt update 

apt install \ 

    ca-certificates \ 

    curl \ 

    gnupg \ 

    lsb-release 

mkdir -p /etc/apt/keyrings 

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg 

echo \ 

  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \ 

  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null 

apt update 

apt install docker-ce docker-ce-cli containerd.io docker-compose-plugin 

 
```

# INSTALL DOCKER-COMPOSE

```shell

curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose 

chmod +x /usr/local/bin/docker-compose 

 

```

# PODMAN

```shell

sudo apt-get install -y podman

sudo apt-get install -y podman-compose

# /etc/containers/registries.conf

unqualified-search-registries = ["docker.io"]




```


# PREPARE DOCKER IMAGE

```shell



docker-compose up  

 

docker-compose down 

 

docker login 

 

docker tag IMAGEID seantywork/NAME 

 

docker push seantywork/NAME

```

# DOCKER PRIVATE

```shell

docker login <address:port> 
```


# DOCKER 

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


# DOCKER-COMPOSE

```shell

# build, name, port,  

# image , volume, runtime 

```


# DOCKER REMOTE

```shell



# on docker daemon host 

 

ssh-keygen 

 

# move id_rsa to the client 

# add id_rsa.pub to authrized_keys 

# on client move id_rsa to ~/.ssh 

 

docker -H ssh://user@host <command> 


```

# DOCKER REMOTE CONTEXT

```shell


docker context create \ 

    --docker host=ssh://user@host \ 

    docker-remote 

 

docker context use docker-remote 

 

docker context use default 

 
```


# KIND INSTALL

```shell


curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v0.14.0/kind-$(uname)-amd64" 

 

chmod +x ./kind 

 

sudo mv ./kind /usr/local/bin/ 

```




# JOIN TOKEN CREATION

```shell
kubeadm token create --print-join-command 

```


# WORKER NODE JOIN

```shell

sudo kubeadm join 10.128.0.37:6443 --token j4eice.33vgvgyf5cxw4u8i \ 

    --discovery-token-ca-cert-hash sha256:37f94469b58bcc8f26a4aa44441fb17196a585b37288f85e22475b00c36f1c61 

 

```


# LABEL WORKER


```shell
sudo kubectl label node worker-node01  node-role.kubernetes.io/worker=worker 

 

sudo kubectl label node worker-node01  ingress-ready=true 

 


```


# IN CASE OF DNS MESSED UP

```shell


sudo kubectl -n kube-system rollout restart deployment coredns 

 

```


# MASTER NODE SCHEDULING


```shell
kubectl taint nodes --all node-role.kubernetes.io/master- 

# or

sudo kubectl taint node <master> node-role.kubernetes.io/control-plane:NoSchedule-

sudo kubectl taint node <master> node-role.kubernetes.io/master:NoSchedule-


```

# PREVENT SCHEDULING


```shell
sudo kubectl cordon <node> 

 

```


# TEAR DOWN CLUSTER


```shell

sudo kubectl drain <node> --delete-local-data --force --ignore-daemonsets 

 
```


# RE-SCHEDULE NODE

```shell
sudo kubectl uncordon <node> 

```

# ON EACH NODE

```shell

sudo kubeadm reset 
```

# HA CLUSTER


```shell

sudo apt-get update 

sudo apt-get install haproxy 

 

sudo vim /etc/haproxy/haproxy.cfg 

```

```shell
# /etc/haproxy/haproxy.cfg 



global 

... 

default 

... 

frontend kubernetes 

bind <kube-lb-domain-or-ip>:<kube-lb-port> # *:<kube-lb-port> 

option tcplog 

mode tcp 

#default_backend kubernetes-master-nodes 

 

 

#acl kubernetes-master-rule hdr(host) -i k8s.cluster.com 

 

 

#use_backend kubernetes-master-nodes if kubernetes-master-rule 

 

 

backend kubernetes-master-nodes 

mode tcp 

balance roundrobin 

option tcp-check 

server k8s-master-0 <kube-master-0>:6443 check fall 3 rise 2 

server k8s-master-1 <kube-master-1>:6443 check fall 3 rise 2 

server k8s-master-2 <kube-master-2>:6443 check fall 3 rise 2 

```

```shell


sudo systemctl restart haproxy 

 

 

# same wj.sh on all nodes 

 

# different mj.sh on the first master node 

 

sudo kubeadm init --apiserver-advertise-address=$MASTER_IP --apiserver-cert-extra-sans="$MASTER_IP,$KUBELBADDR" --pod-network-cidr=$POD_CIDR --control-plane-endpoint "$KUBELBADDR:$KUBELBPORT"  --node-name "$NODENAME" --ignore-preflight-errors Swap 

 
```

# SCP CERTS


```shell


USER=<user-on-host> # customizable 

# Set the control_plane_ips to all other master node ips or hostnames 

CONTROL_PLANE_IPS="<addr1> <addr2>" 

for host in ${CONTROL_PLANE_IPS}; do 

    scp /etc/kubernetes/pki/ca.crt "${USER}"@$host: 

    scp /etc/kubernetes/pki/ca.key "${USER}"@$host: 

    scp /etc/kubernetes/pki/sa.key "${USER}"@$host: 

    scp /etc/kubernetes/pki/sa.pub "${USER}"@$host: 

    scp /etc/kubernetes/pki/front-proxy-ca.crt "${USER}"@$host: 

    scp /etc/kubernetes/pki/front-proxy-ca.key "${USER}"@$host: 

    scp /etc/kubernetes/pki/etcd/ca.crt "${USER}"@$host:etcd-ca.crt 

    scp /etc/kubernetes/pki/etcd/ca.key "${USER}"@$host:etcd-ca.key 

    scp /etc/kubernetes/admin.conf "${USER}"@$host: 

done 

 


```


# MV CERTS ON EACH MASTER NODE


```shell


USER=<user-on-host> # customizable 

mkdir -p /etc/kubernetes/pki/etcd 

mv /home/${USER}/ca.crt /etc/kubernetes/pki/ 

mv /home/${USER}/ca.key /etc/kubernetes/pki/ 

mv /home/${USER}/sa.pub /etc/kubernetes/pki/ 

mv /home/${USER}/sa.key /etc/kubernetes/pki/ 

mv /home/${USER}/front-proxy-ca.crt /etc/kubernetes/pki/ 

mv /home/${USER}/front-proxy-ca.key /etc/kubernetes/pki/ 

mv /home/${USER}/etcd-ca.crt /etc/kubernetes/pki/etcd/ca.crt 

mv /home/${USER}/etcd-ca.key /etc/kubernetes/pki/etcd/ca.key 

mv /home/${USER}/admin.conf /etc/kubernetes/admin.conf 

 

```


# JOIN MASTER NODE


```shell


sudo kubeadm join 10.128.0.37:6443 --token j4eice.33vgvgyf5cxw4u8i \ 

    --discovery-token-ca-cert-hash sha256:37f94469b58bcc8f26a4aa44441fb17196a585b37288f85e22475b00c36f1c61 \ 

    --control-plane --node-name <name> 

 

# admin.conf -> .kube/config 
```


# JOIN WORKER NODE


```shell
sudo kubeadm join 10.128.0.37:6443 --token j4eice.33vgvgyf5cxw4u8i \ 

    --discovery-token-ca-cert-hash sha256:37f94469b58bcc8f26a4aa44441fb17196a585b37288f85e22475b00c36f1c61 \ 

    --node-name <name> 

 


```

# CNIS


```shell

kubectl apply -f  <CNI> ex) https://docs.projectcalico.org/manifests/calico.yaml , "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')" , https://raw.githubusercontent.com/aojea/kindnet/master/install-kindnet.yaml 

 
```


# KIND RUN


```yaml

# Kind yaml structure example



kindcluster.yaml 

 

kind: Cluster 

 

apiVersion: kind.x-k8s.io/v1alpha4 

 

nodes: 

 

 - role: control-plane 

     kubeadmConfigPatches: 

  - | 

    kind: InitConfiguration 

    nodeRegistration: 

      kubeletExtraArgs: 

        node-labels: "ingress-ready=true" 

  extraPortMappings: 

  - containerPort: 80 

    hostPort: 80 

    protocol: TCP 

  - containerPort: 443 

    hostPort: 443 

    protocol: TCP 

 - role: worker 

 

 - role: worker
```

```shell
kind create cluster --name kindcluster --config ./kindcluster.yaml --image=kindest/node:v1.21.12 

 
```

# KUBECTL DEPLOYMENT


```shell
kubectl apply -f <yamls> 
```

# PORT FORWARD

```shell
kubectl port-forward resource/name port
```


# KUBECTL INGRESS


```shell
kubectl label node <node> ingress-ready=true 

 

kubectl apply -f <controller> ex) https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml 

 

kubectl apply -f ingress.yaml 


```

# TLS INGRESS NEED SECRET


```shell


# self singed certs 

 

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./tls.key -out ./tls.crt -subj "/CN=localhost" 

 

kubectl create secret tls --save-config tls-openssl --key ./tls.key --cert ./tls.crt 

 

# include $HOME .kube config -- remote kubectl and switching 

 

kubectl config use-context <context-name

```


# TURNING OFF

```shell

kubectl delete --all ingress, services, deployments 

 

kind delete cluster --name NAME 

 

docker system prune -a  

```


# CHECK


```shell
systemctl status docker 

systemctl status kubelet 

```

# SECRET REG


```shell

kubectl create secret generic <regcred> \ 

    --from-file=.dockerconfigjson=<path/to/.docker/config.json> \ 

    --type=kubernetes.io/dockerconfigjson 

 

kubectl create secret docker-registry <pull_secret_name> \ 

    --docker-server=<registry_server> \ 

    --docker-username=<user_name> \ 

    --docker-password=<password> \ 

```


# K8S COMPONENTS

```shell


ingress controller -> ingress -> svc 

svc -> dpl, stf  

secret -> tls, reg -> cert&key, credentials 

vol -> pv[k8sdiskpath], storageclass -> stf, volmount[containerpath] = volclaim = storageclass 

```

# DEPLOYMENT EXAMPLE


```yaml
apiVersion: apps/v1 

kind: Deployment 

metadata: 

  name: db 

spec: 

  selector: 

    matchLabels: 

      app: db 

  replicas: 1 

  template: 

    metadata: 

      labels: 

        app: db 

    spec: 

      imagePullSecrets: 

        - name: docker-secret 

      containers: 

        - name: db 

          image: seantywork/db 

          ports: 

          - containerPort: 3306 

```


# SERVICE EXAMPLE


```yaml

apiVersion: v1 

kind: Service 

metadata: 

  name: db 

  labels: 

    app: db 

spec: 

  type: ClusterIP 

  ports: 

  - port: 3306 

    targetPort: 3306 

    protocol: TCP 

  selector: 

    app: db 

```


# SERVICE IN DIFFERENT NAMESPACE


```shell

<serivce_name>.<namespace_name> 
```

# NODE SELECTOR & AFFINITY


```yaml


apiVersion: v1 

kind: Pod 

 

.... 

 

spec: 

  nodeSelector:  

    region: east 

    type: user-node 

```


```yaml

apiVersion: v1 

kind: Pod 

metadata: 

  name: with-node-affinity 

spec: 

  affinity: 

    nodeAffinity: 

      requiredDuringSchedulingIgnoredDuringExecution: 

        nodeSelectorTerms: 

        - matchExpressions: 

          - key: topology.kubernetes.io/zone 

            operator: In 

            values: 

            - antarctica-east1 

            - antarctica-west1 

 


```


# ENV


```yaml
apiVersion: apps/v1 

kind: Deployment 

 

.... 

 

 

    spec: 

      containers: 

        - name: kibana 

          image: docker.elastic.co/kibana/kibana:7.11.0 

          env: 

          - name: ELASTICSEARCH_HOSTS 

            value: http://elasticsearch:9200 

          imagePullPolicy: Always 

          ports: 

          - containerPort: 5601 


```


# COMMAND


```yaml

.... 

 

containers: 

  - name: mysqldump 

    image: mysql 

    command: ["/bin/sh", "-c"] 

    args: 

      - echo starting; 

        ls -la /backups; 

        mysqldump --host=... -r /backups/file.sql db_name; 

        ls -la /backups; 

        echo done; 

    volumeMounts: 

      - ... 

 

```

# NODEPORT


```yaml
kind: Service
apiVersion: v1
metadata:
  name: nodeport-test
spec:
  type: NodePort
  selector:
    app: tgtraffic
  ports:
    - nodePort: 30505
      port: 5005
      targetPort: 5005

```

# INGRESS

```yaml

apiVersion: networking.k8s.io/v1 

kind: Ingress 

metadata: 

  name: ingress 

spec: 

  tls: 

  - hosts: 

    - usagecorpus.com 

    secretName: uc-tls-secret 

  - hosts: 

    - www.usagecorpus.com 

    secretName: uc-tls-secret 

  - hosts: 

    - ptt.usagecorpus.com 

    secretName: ptt-tls-secret 

  rules: 

  - host: "usagecorpus.com" 

    http: 

      paths: 

        - path: / 

          pathType: Prefix 

          backend: 

            service: 

              name: traffic 

              port: 

                number: 5005 

  - host: "www.usagecorpus.com" 

    http: 

      paths: 

        - path: / 

          pathType: Prefix 

          backend: 

            service: 

              name: traffic 

              port: 

                number: 5005 

  - host: "ptt.usagecorpus.com" 

    http: 

      paths: 

        - path: / 

          pathType: Prefix 

          backend: 

            service: 

              name: trafficph 

              port: 

                number: 5006 


```


# CONFIGMAP


```yaml

apiVersion: v1
data:
  allow-snippet-annotations: "true"
  use-forwarded-headers: "true"
  compute-full-forwarded-for: "true"
  keep-alive: "20"
kind: ConfigMap
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","data":{"allow-snippet-annotations":"true","use-forwarded-headers":"true"},"kind":"ConfigMap","metadata":{"annotations":{},"creationTimestamp":"2022-11-23T07:56:59Z","labels":{"app.kubernetes.io/component":"controller","app.kubernetes.io/instance":"ingress-nginx","app.kubernetes.io/name":"ingress-nginx","app.kubernetes.io/part-of":"ingress-nginx","app.kubernetes.io/version":"1.5.1"},"name":"ingress-nginx-controller","namespace":"ingress-nginx","resourceVersion":"383","uid":"08673e9a-bdba-4a5a-9dda-a7f470d6214e"}}
  creationTimestamp: "2022-11-23T07:56:59Z"
  labels:
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: ingress-nginx
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
    app.kubernetes.io/version: 1.5.1
  name: ingress-nginx-controller
  namespace: ingress-nginx
  resourceVersion: "24225834"
  uid: 08673e9a-bdba-4a5a-9dda-a7f470d6214e
```

```yaml


apiVersion: v1 

kind: ConfigMap 

metadata: 

  namespace: logging 

  name: elasticsearch-data-config 

  labels: 

    app: elasticsearch 

    role: data 

data: 

  elasticsearch.yml: |- 

    cluster.name: ${CLUSTER_NAME} 

    node.name: ${NODE_NAME} 

    discovery.seed_hosts: ${NODE_LIST} 

    cluster.initial_master_nodes: ${MASTER_NODES} 

    network.host: 0.0.0.0 

    node: 

      master: false 

      data: true 

      ingest: false 

    xpack.security.enabled: true 

    xpack.monitoring.collection.enabled: true 


```


```shell

# create


kubectl create configmap ${CONFIGMAP_NAME} --from-file=${FILE} --from-file=${FILE}


```


```shell
# mount

apiVersion: apps/v1
kind: Deployment
metadata:
  name: clusterdebugger
spec:
  selector:
    matchLabels:
      app: clusterdebugger
  replicas: 1
  template:
    metadata:
      labels:
        app: clusterdebugger
    spec:
      imagePullSecrets:
        - name: harbor-secret
      containers:
        - name: clusterdebugger
          image: harbor.mipllab.com/library/clusterdebugger
          volumeMounts:
          - mountPath: /tmp
            name: debugger-mount
          imagePullPolicy: Always
          ports:
          - containerPort: 6700
      volumes:
      - name: debugger-mount
        configMap: 
          name: debugger-mount
          items:
            - key: usercontent.c
              path: usercontent.c
            - key: usercontent.input
              path: usercontent.input

```



# SECRET EXAMPLE (TLS)

```shell
apiVersion: v1 

data: 

  tls.crt: ./tls.crt 

  tls.key: ./tls.key 

kind: Secret 

metadata: 

  name: uc-tls-secret 

  namespace: default 

type: kubernetes.io/tls 

```

# ANNOTATION

```yaml

apiVersion: networking.k8s.io/v1 

kind: Ingress 

metadata: 

  name: minimal-ingress 

  annotations: 
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-http-version : "1.1"
    nginx.ingress.kubernetes.io/proxy-request-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/rewrite-target: / 

spec: 

  ingressClassName: nginx-example 

  rules: 

  - http: 

      paths: 

      - path: /testpath 

        pathType: Prefix 

        backend: 

          service: 

            name: test 

            port: 

              number: 80 


```

# DEPLOYMENT EXAMPLE (VOLUME)


```yaml

apiVersion: apps/v1 

kind: Deployment 

metadata: 

  name: db 

spec: 

  selector: 

    matchLabels: 

      app: db 

  replicas: 1 

  template: 

    metadata: 

      labels: 

        app: db 

    spec: 

      imagePullSecrets: 

        - name: docker-secret 

      volumes: 

        - name: db-pv-storage 

          persistentVolumeClaim: 

            claimName: dbpvc 

      containers: 

        - name: db 

          image: seantywork/db 

          ports: 

          - containerPort: 3306 

          volumeMounts: 

          - mountPath: "/var/lib/mysql" 

            name: db-pv-storage 

```

# STATEFULSET EXAMPLE


```yaml
apiVersion: apps/v1 

kind: StatefulSet 

metadata: 

  name: dbstf 

spec: 

  selector: 

    matchLabels: 

      app: dbstf 

  serviceName: "dbstf" 

  replicas: 1 

  template: 

    metadata: 

      labels: 

        app: dbstf 

    spec: 

      terminationGracePeriodSeconds: 10 

      containers: 

      - name: dbstf 

        image: seantywork/db 

        ports: 

        - containerPort: 3306 

        volumeMounts: 

        - name: dbpvc 

          mountPath: /var/lib/mysql 

  volumeClaimTemplates: 

  - metadata: 

      name: dbpvc 

    spec: 

      accessModes: ["ReadWriteOnce"] 

      storageClassName: "manual" 

      resources: 

        requests: 

          storage: 3Gi 


```

# STORAGECLASS EXAMPLE (DEFAULT)

```shell

kind: StorageClass 

apiVersion: storage.k8s.io/v1 

metadata: 

  annotations: 

    storageclass.kubernetes.io/is-default-class: "true" 

  name: pv2-local-storageclass 

provisioner: kubernetes.io/no-provisioner 

volumeBindingMode: WaitForFirstConsumer 

```


# STORAGECLASS EXAMPLE (DEFAULT NFS)

```shell

helm repo add nfs-subdir-external-provisioner https://kubernetes-sigs.github.io/nfs-subdir-external-provisioner/ 

 

helm install nfs-subdir-external-provisioner nfs-subdir-external-provisioner/nfs-subdir-external-provisioner \ 

    --set nfs.server=x.x.x.x \ 

    --set nfs.path=/exported/path 

# yaml
```

```yaml
kind: StorageClass 

apiVersion: storage.k8s.io/v1 

metadata: 

  annotations: 

    storageclass.kubernetes.io/is-default-class: "true" 

  name: nfs-default-storageclass 

provisioner: k8s-sigs.io/nfs-subdir-external-provisioner # cluster.local/nfs-subdir-external-provisioner 

allowVolumeExpansion: true 

volumeBindingMode: Immediate 

```

# PERSISTENT VOLUME EXAMPLE (HOSTPATH)

```yaml

apiVersion: v1 

kind: PersistentVolume 

metadata: 

  name: dbpv 

  labels: 

    type: local 

spec: 

  storageClassName: manual 

  capacity: 

    storage: 10Gi 

  accessModes: 

    - ReadWriteOnce 

  hostPath: 

    path: "/home/styw/project/k8s/vol_host" 

```

# PERSISTENT VOLUME EXAMPLE (LOCALSTORAGE) 

```yaml

apiVersion: v1 

kind: PersistentVolume 

metadata: 

  name: pv1-local 

spec: 

  capacity: 

    storage: 64Gi 

  accessModes: 

  - ReadWriteOnce 

  persistentVolumeReclaimPolicy: Recycle 

  storageClassName: local-storage 

  local: 

    path: /data/volumes/pv1 

  nodeAffinity: 

    required: 

      nodeSelectorTerms: 

      - matchExpressions: 

        - key: kubernetes.io/hostname 

          operator: In 

          values: 

          - worker1-lw 

```

# PERSISTENT VOLUME EXAMPLE (NFS) 

```yaml
apiVersion: v1 

kind: PersistentVolume 

metadata: 

  name: dbpv 

spec: 

  capacity: 

    storage: 10Gi 

  volumeMode: Filesystem 

  accessModes: 

    - ReadWriteMany 

  persistentVolumeReclaimPolicy: Recycle 

  storageClassName: nfs 

  mountOptions: 

    - hard 

    - nfsvers=4.1 

  nfs: 

    path: /opt/k8s-pods/data 

    server: 192.168.1.40 


```

# PERSISTENT VOLUME CLAIM EXAMPLE (HOSTPATH) 

```yaml

apiVersion: v1 

kind: PersistentVolumeClaim 

metadata: 

  name: dbpvc 

spec: 

  storageClassName: manual 

  accessModes: 

    - ReadWriteOnce 

  resources: 

    requests: 

      storage: 3Gi 

```

# PERSISTENT VOLUME CLAIM EXAMPLE (LOCALSTORAGE) 

```yaml
kind: PersistentVolumeClaim 

apiVersion: v1 

metadata: 

  name: pv1-local-claim 

spec: 

  accessModes: 

  - ReadWriteOnce 

  storageClassName: local-storage 

  resources: 

    requests: 

      storage: 64Gi 

```

# PERSISTENT VOLUME CLAIM EXAMPLE (NFS) 

```yaml

apiVersion: v1 

kind: PersistentVolumeClaim 

metadata: 

  name: dbpvc 

spec: 

  storageClassName: nfs 

  accessModes: 

    - ReadWriteMany 

  resources: 

    requests: 

      storage: 10Gi 

```

# SYSBOX - FOR DIND 

```shell


# install 

wget https://downloads.nestybox.com/sysbox/releases/v0.5.0/sysbox-ce_0.5.0-0.linux_amd64.deb 

 

apt install jq 

apt install ./sysbox-ce_0.5.0-0.linux_amd64.deb 

 

systemctl status docker 

systemctl status sysbox 

 

docker-compose.yaml -- add runtime: sysbox-runc

```

# ON K8S

```shell
kubectl label node <node-name> sysbox-install=yes 

kubectl apply -f https://raw.githubusercontent.com/nestybox/sysbox/master/sysbox-k8s-manifests/sysbox-install.yaml 

 

```

# REMOTE KUBECTL

```shell



kubectl -n kube-system create serviceaccount <service-account-name> 

 

kubectl create clusterrolebinding <clusterrolebinding-name> --clusterrole=cluster-admin --serviceaccount=kube-system:<service-account-name> 

 

export TOKENNAME=$(kubectl -n kube-system get serviceaccount/<service-account-name> -o jsonpath='{.secrets[0].name}') 

 

export TOKEN=$(kubectl -n kube-system get secret $TOKENNAME -o jsonpath='{.data.token}' | base64 --decode) 

 

curl -k -H "Authorization: Bearer $TOKEN" -X GET "https://<KUBE-API-IP>:6443/api/v1/nodes" | json_pp 

 

kubectl config set-credentials <service-account-name> --token=$TOKEN 

 

kubectl config set-context --current --user=<service-account-name> 

 

# erase TLS auth info and add to cluster the option insecure-skip-tls-verify: true 

 

# then copy and paste the $HOME .kube config and modify server address 

 

# or just copy the whole config with a correct API server address 

 

```


# KUBE PROXY

```shell

kubectl proxy --address 0.0.0.0 --accept-hosts '.*' --port=<port> 

 
```

# KUBECTL REMOTE WITH TLS AND CUSTOM DOMAIN, IP

```shell

kubectl -n kube-system get configmap kubeadm-config -o jsonpath='{.data.ClusterConfiguration}' > kubeadm.yaml 

 

# edit certSANS 

 

# on control plane 

# remove below 

 

/etc/kubernetes/pki/apiserver.{crt,key} ~ 

 

kubeadm init phase certs apiserver --config kubeadm.yaml 

 

docker ps | grep kube-apiserver | grep -v pause 

 

docker kill <containerID> 

 

# or 

 

crictl pods | grep kube-apiserver | cut -d' ' -f1 

 

crictl stopp <pod-id> 

 

crictl rmp <pod-id> 

 

# wait till kube-system pods to restart and accessible by the dns 

# or

# on all master nodes

# remove current apiserver certificates
sudo rm /etc/kubernetes/pki/apiserver.*

# generate new certificates
sudo kubeadm init phase certs apiserver --apiserver-cert-extra-sans="ADDR1,ADDR2,ADDR3"
 


```

# KUBEADM RENEW CERTIFICATE

```shell

# on all control plane nodes

kubeadm certs renew all

# then restart

mv /etc/kubernetes/manifest/* mv /etc/kubernetes/manifest_tmp

# wait 20+ seconds

mv /etc/kubernetes/manifest_tmp/* mv /etc/kubernetes/manifest


```

# KUBEADM UPGRADE

```shell

# on the first master nodes

sudo apt-mark unhold kubeadm && \
sudo apt-get update && sudo apt-get install -y kubeadm=1.27.x-00 && \
sudo apt-mark hold kubeadm

sudo kubeadm upgrade apply v1.27.x

sudo kubectl drain <node-to-drain> --ignore-daemonsets

sudo apt-mark unhold kubelet kubectl && \
sudo apt-get update && sudo apt-get install -y kubelet=1.27.x-00 kubectl=1.27.x-00 && \
sudo apt-mark hold kubelet kubectl

sudo systemctl daemon-reload
sudo systemctl restart kubelet

sudo kubectl uncordon <node-to-uncordon>

# on other master nodes 

sudo apt-mark unhold kubeadm && \
sudo apt-get update && sudo apt-get install -y kubeadm=1.27.x-00 && \
sudo apt-mark hold kubeadm

sudo kubeadm upgrade node

sudo kubectl drain <node-to-drain> --ignore-daemonsets

sudo apt-mark unhold kubelet kubectl && \
sudo apt-get update && sudo apt-get install -y kubelet=1.27.x-00 kubectl=1.27.x-00 && \
sudo apt-mark hold kubelet kubectl

sudo systemctl daemon-reload
sudo systemctl restart kubelet

sudo kubectl uncordon <node-to-uncordon>

# on worker nodes

sudo apt-mark unhold kubeadm && \
sudo apt-get update && sudo apt-get install -y kubeadm=1.27.x-00 && \
sudo apt-mark hold kubeadm

sudo kubeadm upgrade node

sudo kubectl drain <node-to-drain> --ignore-daemonsets

sudo apt-mark unhold kubelet kubectl && \
sudo apt-get update && sudo apt-get install -y kubelet=1.27.x-00 kubectl=1.27.x-00 && \
sudo apt-mark hold kubelet kubectl

sudo systemctl daemon-reload
sudo systemctl restart kubelet

sudo kubectl uncordon <node-to-uncordon>


```

# VM 

```shell

# iso 

# processor 

# memory 

# storage 

# network: bridge  

```


# CLOUD (AWS)

```shell

# EC2: create EC2 instance  

# instance details: check instace details to get access 

# elastic block store: it has volume, instance info 

# network & security: check network & security  

# network interface: it has vpc, subnet, instance info 

# vpc: EC2 must be created in a same vpc 

# subnet: EC2 must be created in a same subnet under the same vpc 

# security group: each EC2 must share the same security(inbound, outbound) rule 

# instance: take care of firewall 

```

# CLOUD (GCP)

```shell

# api 

# oauth 
```

# AWS EKS

```shell
# eksctl version 0.106.0 

# create IAM user and role related to EKS and Adminaccess 

 

curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" 

unzip awscliv2.zip 

sudo ./aws/install 

 

curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp 

 

mv /tmp/eksctl /usr/local/bin 

 

aws configure 

 

eksctl create cluster -f ekscluster.yaml 

 
```

# CUSTOM REGISTRY - HARBOR 

```shell

 

curl -s https://api.github.com/repos/goharbor/harbor/releases/latest | grep browser_download_url | cut -d '"' -f 4 | grep '\.tgz$' | wget -i - 

 

tar xvzf harbor-offline-installer*.tgz 

 

cp harbor.yml.tmpl harbor.yml 

 

# change necessary info 

 


```

```shell

# kubernetes private nodeport

helm repo add harbor https://helm.goharbor.io


helm install go-harbor harbor/harbor --set expose.type=nodePort --set expose.tls.auto.commonName=192.168.50.94 --set externalURL=https://192.168.50.94:30003 --set persistence.enabled=false --set imagePullPolicy=Always # --set persistence.enabled=true --set persistence.persistentVolumeClaim.registry.size=10Gi --set persistence.persistentVolumeClaim.chartmuseum.size=5Gi --set persistence.persistentVolumeClaim.jobservice.size=5Gi --set persistence.persistentVolumeClaim.database.size=5Gi --set persistence.persistentVolumeClaim.redis.size=5Gi


sudo kubectl exec go-harbor-nginx-9556767d6-tm89q -- cat /etc/nginx/cert/ca.crt > ca.crt 


mkdir -p /etc/docker/certs.d/192.168.50.94:30003

/bin/cp -Rf ca.crt /etc/docker/certs.d/192.168.50.94:30003/



```

# HELM

```shell

curl https://baltocdn.com/helm/signing.asc | sudo apt-key add -  

 

sudo apt install apt-transport-https --yes  

 

echo "deb https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list  

 

sudo apt update  

 

sudo apt install helm  
```

# JENKINS

```shell

sudo apt install -y openjdk-11-jdk openjdk-11-jre 

 

wget -q -O - https://pkg.jenkins.io/debian-stable/jenkins.io.key | sudo apt-key add - 

 

sudo sh -c 'echo deb http://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list' 

 

sudo apt update 

 

sudo apt -y install jenkins 

 

# on k8s 

 

helm repo add jenkins https://charts.jenkins.io 

 

helm repo update 

 

helm install jkns jenkins/jenkins 

```


# PROMETHEUS & GRAFANA 

```shell

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts  

  

helm repo add stable https://charts.helm.sh/stable  

 

helm repo update  

 

helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack -f ./kube-prometheus-stack/value.yaml 



kubectl port-forward deployment/prometheus-grafana 3000 

 

# Prometheus alone 

 

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 

 

helm repo update 

 

helm install prometheus prometheus-community/prometheus 

 

# Grafana local 

 

sudo apt install -y apt-transport-https 

 

sudo apt install -y software-properties-common wget 

 

sudo wget -q -O /usr/share/keyrings/grafana.key https://packages.grafana.com/gpg.key 

 

echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://packages.grafana.com/enterprise/deb stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list 

 

sudo apt update 

 

sudo apt install grafana-enterprise 

 

sudo service grafana-server start 

 

config -> /etc/grafana/grafana.ini 

 

# localhost:3000 

 

username: admin 

password: prom-operator 

 

```

# OCTANT

```shell

wget https://github.com/vmware-tanzu/octant/releases/download/v0.24.0/octant_0.24.0_Linux-64bit.deb 

 

dpkg -i octant_0.24.0_Linux-64bit.deb 


```


# REDIS

```yaml

version: "3"

services:

    redis:
      image: redis:7.0.8
      container_name: redis
      command:
        - /bin/sh
        - -c
        - redis-server --requirepass "youdonthavetoknow"
      volumes:
        - ./redis:/var/lib/redis/data
        - ./redis.conf:/usr/local/etc/redis/redis.conf
      ports:
        - "6379:6379"
```

```shell

# redis.conf

port              6379
daemonize         yes
save              60 1
bind              0.0.0.0
tcp-keepalive     300
dbfilename        dump.rdb
dir               ./
rdbcompression    yes

```

# KAFKA & ZOOKEEPER

```shell
helm repo add bitnami https://charts.bitnami.com/bitnami 

 

helm install zookeeper bitnami/zookeeper --set replicaCount=1 --set auth.enabled=false --set allowAnonymousLogin=true 

 

helm install kafka bitnami/kafka --set zookeeper.enabled=false --set replicaCount=1 --set externalZookeeper.servers=ZOOKEEPER-SERVICE-NAME 

 

kubectl --namespace default exec -it $POD_NAME -- kafka-console-consumer.sh --bootstrap-server KAFKA-SERVICE-NAME:9092 --topic mytopic 

 

kubectl --namespace default exec -it $POD_NAME -- kafka-console-producer.sh --broker-list KAFKA-SERVICE-NAME:9092 --topic mytopic 

 

# or kafkacat like below 

 

kafkacat -P -b KAFKA-SERVICE-NAME:9092 -t mytopic 

 

kafkacat -C -b KAFKA-SERVICE-NAME:9092 -t mytopic 

```
```yaml
# single node

---

version: "3"
services:
  zookeeper:
    image: 'bitnami/zookeeper:3.7'
    container_name: zookeeper
    ports:
      - '2181:2181'
    environment:
      - ALLOW_ANONYMOUS_LOGIN=yes
    volumes:
      - ./zook:/data
  kafka:
    image: 'bitnami/kafka:3.3'
    container_name: kafka
    ports:
      - '9092:9092'
    environment:
      - KAFKA_BROKER_ID=1
      - KAFKA_CFG_LISTENERS=PLAINTEXT://:9092
      - KAFKA_CFG_ADVERTISED_LISTENERS=PLAINTEXT://172.17.80.95:9092
      - KAFKA_CFG_ZOOKEEPER_CONNECT=zookeeper:2181
      - ALLOW_PLAINTEXT_LISTENER=yes
    volumes:
      - ./data:/var/lib/kafka/data
    depends_on:
      - zookeeper


```

# ELASTIC SEARCH & KIBANA 

```shell

helm repo add bitnami https://charts.bitnami.com/bitnami 

 

sudo helm install elasticsearch  bitnami/elasticsearch 

 

sudo helm install kibana bitnami/kibana --set elasticsearch.hosts[0]=elasticsearch --set elasticsearch.port=9200 

 

```

```yaml

version: "3"



services:

        elasticsearch:

                image: elasticsearch:8.6.1

                environment:

                        - xpack.security.enabled=true

                        - discovery.type=single-node

                        - "ES_JAVA_OPTS=-Xms2g -Xmx2g"

                        - ELASTIC_PASSWORD=youdonthavetoknow


                container_name: elasticsearch

                ports:

                        - "9200:9200"

                volumes:

                        - elastic_data:/usr/share/elasticsearch/data

volumes:

        elastic_data:

```
```shell
# set password for kibana

docker exec -it elasticsearch /bin/bash

bin/elasticsearch-set-password [ auto | interactive ]

```

```yaml

version: "3"
services:
    kibana:
        image: kibana:8.5.3
        container_name: kibana
        restart: always
        ports:
            - 5601:5601
        environment:
            - ELASTICSEARCH_USERNAME="kibana_system"
            - ELASTICSEARCH_PASSWORD="youdonthavetoknow"
            - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
            - XPACK_MONITORING_ENABLED=true
            - XPACK_MONITORING_COLLECTION_ENABLED=true
            - XPACK_SECURITY_ENABLED=true
        networks:
            - network1

networks:
    network1:
        name: elastic_default
        external: true


```

# GPU

```shell

# nvidia cuda driver

# build prerequisite

sudo apt-get install linux-headers-$(uname -r) build-essential

# simple way

# curl from https://www.nvidia.com/download/index.aspx 

# and install run

# host driver 

# ubuntu 

sudo apt-get install linux-headers-$(uname -r) 

 

distribution=$(. /etc/os-release;echo $ID$VERSION_ID | sed -e 's/\.//g') 

 

wget https://developer.download.nvidia.com/compute/cuda/repos/$distribution/x86_64/cuda-keyring_1.0-1_all.deb 

 

sudo dpkg -i cuda-keyring_1.0-1_all.deb 

 

sudo apt-get update 

 

sudo apt-get -y install cuda-drivers 

 

#centos 

sudo dnf install -y tar bzip2 make automake gcc gcc-c++ pciutils elfutils-libelf-devel libglvnd-devel iptables firewalld vim bind-utils wget 

 

sudo yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm 

 

distribution=rhel7 

 

ARCH=$( /bin/arch ) 

 

sudo yum-config-manager --add-repo http://developer.download.nvidia.com/compute/cuda/repos/$distribution/${ARCH}/cuda-$distribution.repo 

 

sudo yum install -y kernel-devel-$(uname -r) kernel-headers-$(uname -r) 

 

sudo yum clean expire-cache 

 

sudo yum install -y nvidia-driver-latest-dkms 

 

# post install 

 

export PATH=/usr/local/cuda-11.8/bin${PATH:+:${PATH}} 

 

export LD_LIBRARY_PATH=/usr/local/cuda-11.8/lib64\ 

                         ${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}} 

 

sudo systemctl enable nvidia-persistenced 

 

 

/usr/bin/nvidia-persistenced --verbose 

 

cat /proc/driver/nvidia/version 

 
# disable noveau

sudo nano /etc/modprobe.d/blacklist-nouveau.conf

```
```shell
# /etc/modprobe.d/blacklist-nouveau.conf
blacklist nouveau
options nouveau modeset=0
```
```shell
sudo update-initramfs -u
sudo reboot
```


# GPU DRIVER INSTALL UNINSTALL


```shell

sudo ubuntu-drivers list

# or, for servers:

sudo ubuntu-drivers list --gpgpu

# install
sudo ubuntu-drivers install nvidia:525

# or for servers:

sudo ubuntu-drivers install --gpgpu nvidia:525-server

# or install GPU API

sudo sh cuda_<VERSION>_linux.run

# or run file

sudo NVIDIA_<VERSION>.run 

```


```shell
# uninstall

sudo apt-get --purge remove "*nvidia*"

sudo /usr/bin/nvidia-uninstall

# or runfile

sudo NVIDIA_<VERSION>.run --uninstall

```

# GPU API

```shell

# nvidia cuda toolkit

# check nvidia-smi cuda version

# visit corresponding https://developer.nvidia.com/cuda-downloads 

wget https://developer.download.nvidia.com/compute/cuda/12.2.0/local_installers/cuda_12.2.0_535.54.03_linux.run

sudo sh cuda_12.2.0_535.54.03_linux.run

# add path and ld path

export PATH="/usr/local/cuda-12.2/bin:$PATH"

# /etc/ld.so.conf

...
include /usr/local/cuda-12.2/lib64
...

sudo ldconfig


# uninstall


/usr/local/cuda/bin/<uninstaller>


```


# GPU CONTAINER



```shell


# install nvidia container toolkit 

 

sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit 


```

```toml
# containerd daemon config /etc/containerd/config.toml


version = 2 

[plugins] 

  [plugins."io.containerd.grpc.v1.cri"] 

    [plugins."io.containerd.grpc.v1.cri".containerd] 

      default_runtime_name = "nvidia" 

  

      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes] 

        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia] 

          privileged_without_host_devices = false 

          runtime_engine = "" 

          runtime_root = "" 

          runtime_type = "io.containerd.runc.v2" 

          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia.options] 

            BinaryName = "/usr/bin/nvidia-container-runtime" 

 
```

```shell
sudo systemctl restart containerd 

``` 

```shell
# crio daemon

# /etc/crio/crio.conf.d/crio.conf

[crio]

  [crio.runtime]
    default_runtime = "nvidia"

    [crio.runtime.runtimes]

      [crio.runtime.runtimes.nvidia]
        runtime_path = "/usr/bin/nvidia-container-runtime"
        runtime_type = "oci"

# or

# /etc/crio/crio.conf

 hooks_dir = [
        "/usr/share/containers/oci/hooks.d",
        "/run/containers/oci/hooks.d",
        "/etc/containers/oci/hooks.d",
 ]
 
 ```

```shell

$ sudo mkdir -p /usr/share/containers/oci/hooks.d 

# or

$ sudo mkdir -p /run/containers/oci/hooks.d

  

$ sudo bash -c  

cat > /usr/share/containers/oci/hooks.d/oci-nvidia-hook.json << EOF 

{ 

    "version": "1.0.0", 

    "hook": { 

        "path": "/usr/bin/nvidia-container-toolkit", 

        "args": ["nvidia-container-toolkit", "prestart"] ,
        
        "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]

    }, 

    "when": { 

        "always": true, 

        "commands": [".*"] 

    }, 

    "stages": ["prestart"] 

} 

EOF 



# or you could use simplified command

curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg \
  && curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
    sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
    sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list \
  && \
    sudo apt-get update
    
    
sudo apt-get install -y nvidia-container-toolkit


sudo nvidia-ctk runtime configure --runtime=docker

sudo systemctl restart docker


sudo nvidia-ctk runtime configure --runtime=containerd


sudo systemctl restart containerd

sudo nvidia-ctk runtime configure --runtime=crio


sudo systemctl restart crio
 

# crio 

/etc/crio/crio.conf.d/99-nvidia.conf

[crio]

  [crio.runtime]
    default_runtime = "nvidia"

    [crio.runtime.runtimes]

      [crio.runtime.runtimes.nvidia]
        runtime_path = "/usr/bin/nvidia-container-runtime"
        runtime_type = "oci"
 


sudo nvidia-ctk runtime configure --runtime=crio --set-as-default --config=/etc/crio/crio.conf.d/99-nvidia.conf
 

/etc/nvidia-container-runtime/config.toml

[nvidia-container-runtime]
runtimes = ["crun", "docker-runc", "runc"]

sudo systemctl restart crio

# docker 

 

sudo docker --gpus all 

# docker-compose

services:
  jupyterlabc:
    image: seantywork/jupyterlabc
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu] 

# kubernetes 

 

kubectl create -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.13.0/nvidia-device-plugin.yml 

 

# helm 

 

helm repo add nvdp https://nvidia.github.io/k8s-device-plugin 

 

helm repo update 

 

helm upgrade -i nvdp nvdp/nvidia-device-plugin \ 

  --namespace nvidia-device-plugin \ 

  --create-namespace \ 

  --version 0.13.0 

 

 

```

```yaml
# gpu deployment 

apiVersion: apps/v1 

kind: Deployment 

metadata: 

  name: clusterdebuggergpu 

spec: 

  selector: 

    matchLabels: 

      app: clusterdebuggergpu 

  replicas: 1 

  template: 

    metadata: 

      labels: 

        app: clusterdebuggergpu 

    spec: 

      nodeSelector: 

        gpu-ready: ready 

      imagePullSecrets: 

        - name: harbor-secret 

      containers: 

        - name: clusterdebuggergpu 

          image: harbor.mipllab.com/library/clusterdebugger 

          resources: 

            limits: 

              nvidia.com/gpu: 1 

          imagePullPolicy: Always 

          ports: 

          - containerPort: 6700 



```



# LIB TORCH

```shell

# https://pytorch.org/get-started/locally/

# cpu

wget https://download.pytorch.org/libtorch/cpu/libtorch-cxx11-abi-shared-with-deps-2.1.1%2Bcpu.zip

unzip 

mv libtorch libtorch-cpu

# gpu

wget https://download.pytorch.org/libtorch/cu121/libtorch-cxx11-abi-shared-with-deps-2.1.1%2Bcu121.zip


# build 

mkdir build
cd build
cmake -DCMAKE_PREFIX_PATH=/absolute/path/to/libtorch .. 
# cmake -DCMAKE_PREFIX_PATH=/home/seantywork/hack/torch-cc/libtorch .. (2.1)



cmake --build . --config Release

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

# IDA

```shell


# download run 

 

chmod  

 

sudo ./ida.run 

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

# GHIDRA

```shell

sudo apt-get install openjdk-17-jdk 

 

wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2_build/ghidra_10.2_PUBLIC_20221101.zip 

 

unzip ghidra_10.2_PUBLIC_20221101.zip -d <target>
```

# WIRESHARK

```shell

sudo apt install wireshark 


```

# TSHARK

```shell

sudo apt install tshark

```


# TCP DUMP TCPDUMP UDP DUMP

```shell

sudo tcpdump -i $IFACE -A -X -c 20 port $PORT


```

```shell

# udpdump

sudo tcpdump -i $IFACE -A -X -c 20 -n udp port 23232


```

# TOR

```shell

# download tar or 

 

wget https://www.torproject.org/dist/torbrowser/11.5.7/tor-browser-linux64-11.5.7_en-US.tar.xz 

 

tar -xvf tor-browser-linux64-11.5.7_en-US.tar.xz 

 
# install command line

apt install apt-transport-https

```


```shell

# /etc/apt/sources.list.d/tor.list

   deb     [arch=amd64 signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org jammy main
   deb-src [arch=amd64 signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org jammy main

```

```shell

wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | sudo tee /usr/share/keyrings/tor-archive-keyring.gpg >/dev/null


apt update

apt install tor deb.torproject.org-keyring

```

# METASPLOIT AND SECURITY TOOLS 

```shell


curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall 

 

sudo chmod 755 msfinstall 

 

sudo ./msfinstall 

 

sudo apt install nmap 

 

git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev 

 

sudo apt install nikto -y 

 
```

# NGROK

```shell

sudo snap install ngrok

ngrok tcp <port>
```

# BURPESUITE

```shell


# download .sh 

 

sudo ./burpsuite_community_linux_v2022_9_5.sh  

 

```

# OWASP ZAP

```shell

# download .zip 

 

tar -xzf ZAP_2.12.0_Linux.tar.gz 


```

# MITMPROXY 

```shell

apt-get -y remove mitmproxy

apt-get -y install python3-pip

pip3 install mitmproxy

export http_proxy=${http_thing}
export https_proxy=${https_thing}

# brower http://mitm.it -> get ca cert

/bin/cp -Rf mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt

update-ca-certificates

mitmproxy

```


# OLD KEY STORE FIX

```shell

for KEY in $(apt-key --keyring /etc/apt/trusted.gpg list | grep -E "(([ ]{1,2}(([0-9A-F]{4}))){10})" | tr -d " " | grep -E "([0-9A-F]){8}\b" ); do K=${KEY:(-8)}; apt-key export $K | sudo gpg --dearmour -o /etc/apt/trusted.gpg.d/imported-from-trusted-gpg-$K.gpg; done
 

 

```

# CLUSTER DEBUGGER

```yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: clusterdebugger
spec:
  selector:
    matchLabels:
      app: clusterdebugger
  replicas: 1
  template:
    metadata:
      labels:
        app: clusterdebugger
    spec:
      containers:
        - name: clusterdebugger
          image: seantywork/clusterdebugger
          imagePullPolicy: Always
          ports:
          - containerPort: 6700
```


```yaml

version: "3"


services:

        clusterdebugger:

                build: .


                container_name: clusterdebugger

                ports:

                        - "6700:6700"

```

```shell
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y ca-certificates curl gnupg lsb-release wget iptables supervisor git vim

RUN apt install -y python3-pip

RUN pip3 install gunicorn

RUN pip3 install flask

RUN pip3 install requests

RUN pip3 install Flask-Session

RUN pip3 install mysql-connector-python

CMD ["tail", "-f", "/dev/null"]

```

# CONTAINER DEBUGGER

```shell

FROM ubuntu:20.04


RUN apt-get update

RUN apt-get install -y build-essential ca-certificates curl git vim

RUN mkdir -p /workspace

WORKDIR /workspace

CMD ["tail","-f","/dev/null"]
```


```yaml
version: "3"

services:

    debugger:
      build: .
      container_name: debugger


```

# ELASTIC SEARCH

```shell

FROM elasticsearch:8.6.1

ENV xpack.security.enabled=true
ENV discovery.type=single-node
ENV ES_JAVA_OPTS="-Xms2g -Xmx2g"
ENV ELASTIC_PASSWORD=estest

EXPOSE 9200

```

```yaml


version: "3"


services:

        elasticsearch:

                build: ./elasticsearch


                container_name: elasticsearch

                ports:

                        - "9200:9200"

                volumes:

                        - ./elasticsearch/data:/usr/share/elasticsearch/data

```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: elasticsearch
  labels:
    app: elasticsearch
spec:
  type: ClusterIP
  ports:
  - port: 9200
    targetPort: 9200
    protocol: TCP
  selector:
    app: elasticsearch
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: elasticsearch
spec:
  selector:
    matchLabels:
      app: elasticsearch
  replicas: 1
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      volumes:
        - name: elasticsearch-storage
          persistentVolumeClaim:
            claimName: pvc-16g-elasticsearch
      imagePullSecrets:
        - name: harbor-secret
      containers:
        - name: elasticsearch
          image: seantywork/elasticsearch
          imagePullPolicy: Always
          ports:
          - containerPort: 9200
          volumeMounts:
          - mountPath: /usr/share/elasticsearch/data
            name: elasticsearch-storage
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc-16g-elasticsearch
spec:
  storageClassName: nfs-default-storageclass
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 16Gi

```

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-16g-elasticsearch
spec:
  capacity:
    storage: 16Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Delete
  storageClassName: nfs-default-storageclass
  mountOptions:
    - hard
    - nfsvers=4.1
  nfs:
    path: /data1/nfs-cluster-vol/es-kbn/elastic/elasticsearch/data
    server: 192.168.0.100


```

# GITLAB

```yaml

version: "3"
services:
  gitlab:
    image: gitlab/gitlab-ce:15.4.6-ce.0
    restart: always
    container_name: gitlab
    hostname: 'gitlab.usagecorpus.com'
    environment:
      GITLAB_OMNIBUS_CONFIG: |
        external_url 'http://gitlab.usagecorpus.com'
    ports:
      - '9367:80'
    volumes:
      - './gitlab-data/config:/etc/gitlab'
      - './gitlab-data/logs:/var/log/gitlab'
      - './gitlab-data/data:/var/opt/gitlab'
    shm_size: '256m'

```


# GPU SET

```shell

#!/bin/bash


# Adjust versions, or, you might even have to directly download driver installtion script 

sudo apt-get install linux-headers-$(uname -r)



distribution=$(. /etc/os-release;echo $ID$VERSION_ID | sed -e 's/\.//g')



wget https://developer.download.nvidia.com/compute/cuda/repos/$distribution/x86_64/cuda-keyring_1.0-1_all.deb



sudo dpkg -i cuda-keyring_1.0-1_all.deb



sudo apt-get update



sudo apt-get -y install cuda-drivers



export PATH=/usr/local/cuda-11.8/bin${PATH:+:${PATH}}



export LD_LIBRARY_PATH=/usr/local/cuda-11.8/lib64\

                         ${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}



sudo systemctl enable nvidia-persistenced



/usr/bin/nvidia-persistenced --verbose



sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit



echo "Now configure container runtime"
echo "Go to the link below to get detailed guidance"
echo "https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html"

```

# HARBOR

```shell

# get the zip? tar?

# untar

# edit harbor.yml

```

```yaml
# harbor.yml

...

hostname: harbor.usagecorpus.com

# http related config
http:
  # port for http, default is 80. If https enabled, this port will redirect to https port
  port: 5001

# https related config
#https:
#  # https port for harbor, default is 443
#  port: 443
#  # The path of cert and key files for nginx
#  certificate: /your/certificate/path
#  private_key: /your/private/key/path

# # Uncomment following will enable tls communication between all harbor components
# internal_tls:
#   # set enabled to true means internal tls is enabled
#   enabled: true
#   # put your cert and key files on dir
#   dir: /etc/harbor/tls/internal

# Uncomment external_url if you want to enable external proxy
# And when it enabled the hostname will no longer used
external_url: https://harbor.usagecorpus.com

# The initial password of Harbor admin
# It only works in first time to install harbor
# Remember Change the admin password from UI after launching Harbor.
harbor_admin_password: Harbor12345

# Harbor DB configuration
database:
  # The password for the root user of Harbor DB. Change this before any production use.
  password: root123
  # The maximum number of connections in the idle connection pool. If it <=0, no idle connections are retained.
  max_idle_conns: 100
  # The maximum number of open connections to the database. If it <= 0, then there is no limit on the number of open connections.
  # Note: the default number of connections is 1024 for postgres of harbor.
  max_open_conns: 900
  # The maximum amount of time a connection may be reused. Expired connections may be closed lazily before reuse. If it <= 0, connections are not closed due to a connection's age.
  # The value is a duration string. A duration string is a possibly signed sequence of decimal numbers, each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
  conn_max_lifetime: 5m
  # The maximum amount of time a connection may be idle. Expired connections may be closed lazily before reuse. If it <= 0, connections are not closed due to a connection's idle time.
  # The value is a duration string. A duration string is a possibly signed sequence of decimal numbers, each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
  conn_max_idle_time: 0

# The default data volume
data_volume: /data2/harbor/harbor_data

...


```


# JENKINS CONTAINER

```shell
FROM ubuntu:20.04

RUN apt update

RUN apt install -y openjdk-11-jre openjdk-11-jdk wget gnupg2 curl

RUN wget -q -O - https://pkg.jenkins.io/debian-stable/jenkins.io.key | apt-key add -

RUN sh -c 'echo deb http://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'

RUN apt update

RUN apt install -y jenkins


RUN curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

RUN chmod +x /usr/local/bin/docker-compose

RUN apt update

RUN apt install -y apt-transport-https ca-certificates curl

RUN curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | tee /etc/apt/sources.list.d/kubernetes.list

RUN apt update

RUN apt install -y ca-certificates curl gnupg lsb-release

RUN mkdir -p /etc/apt/keyrings

RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

RUN echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

RUN apt update

RUN apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

RUN mkdir /root/.ssh


EXPOSE 8080

VOLUME /var/run/docker.sock
VOLUME /root/.jenkins
VOLUME /root/.ssh

WORKDIR /home

CMD ["jenkins"]

```

```yaml

version: "3"

services:
        jenkins:
                build: ./JK
                container_name: jenkins
                ports:

                        - "8080:8080"
             


                volumes:
                        - /var/run/docker.sock:/var/run/docker.sock
                        - ./JK/jenkins_data:/root/.jenkins
                        - /home/tomcat/.ssh:/root/.ssh


```


# JUPYTER LAB

```yaml
version: "3"

services:

        jupyter:
                build: ./build_jupyter
                container_name: jupyter
                ports:
                        - "8888:8888"
                volumes:
                        - ./jupyter:/root


```

```shell
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update

RUN apt install -y git

RUN apt install -y vim

RUN apt install -y curl

RUN apt install -y gnupg

RUN apt install -y python3-pip

RUN pip3 install jupyterlab==3.5.1
RUN pip3 install gekko==1.0.5
RUN pip3 install beautifulsoup4==4.11.2
RUN pip3 install keras==2.11.0
RUN pip3 install matplotlib==3.6.2
RUN pip3 install numpy==1.23.5
RUN pip3 install opencv-python==4.6.0.66
RUN pip3 install pandas==1.5.2
RUN pip3 install plotly==5.11.0
RUN pip3 install torch==1.13.1
RUN pip3 install torchvision==0.14.1
RUN pip3 install scikit-learn==1.1.3
RUN pip3 install scipy==1.9.3
RUN pip3 install seaborn==0.12.1
RUN pip3 install statsmodels==0.13.5
RUN pip3 install tensorflow==2.11.0
RUN pip3 install xgboost==1.7.1
RUN pip3 install requests==2.28.1
RUN pip3 install urllib3==1.26.13
RUN pip3 install selenium==4.7.2
RUN pip3 install mysql-connector-python==8.0.31
RUN pip3 install elasticsearch==8.5.2
RUN pip3 install kafka-python==2.0.2


CMD ["jupyter","lab","--ip","0.0.0.0","--no-browser","--port=8888","--allow-root"]


```

```yaml

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-jupyter
  annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "0"

spec:
  rules:
  - host: jupyter.usagecorpus.com
    http:
      paths:
        - path: /
          pathType: Prefix
          backend:
            service:
              name: jupyter
              port:
                number: 8888
```


```yaml

apiVersion: v1
kind: Service
metadata:
  name: jupyter
  labels:
    app: jupyter
spec:
  type: ClusterIP
  ports:
  - port: 8888
    targetPort: 8888
    protocol: TCP
  selector:
    app: jupyter
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jupyter
spec:
  selector:
    matchLabels:
      app: jupyter
  replicas: 1
  template:
    metadata:
      labels:
        app: jupyter
    spec:
      nodeSelector:
        gpu-ready1: ready
      volumes:
        - name: jupyter-storage-jupyter
          persistentVolumeClaim:
            claimName: pvc-8g-jupyter-jupyter
      imagePullSecrets:
      - name: harbor-secret
      containers:
        - name: jupyter
          image: seantywork/jupyter
          resources:
            limits:
              nvidia.com/gpu: 1
          imagePullPolicy: Always
          ports:
          - containerPort: 8888
          volumeMounts:
          - mountPath: /root
            name: jupyter-storage-jupyter
```


```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-8g-jupyter-jupyter
spec:
  capacity:
    storage: 8Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Delete
  storageClassName: nfs-default-storageclass
  mountOptions:
    - hard
    - nfsvers=4.1
  nfs:
    path: /data1/nfs-cluster-vol/jupyter/jupyter
    server: 192.168.0.100
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc-8g-jupyter-jupyter
spec:
  storageClassName: nfs-default-storageclass
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 8Gi

```


```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-16g-jupyter-mldldb
spec:
  capacity:
    storage: 16Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Delete
  storageClassName: nfs-default-storageclass
  mountOptions:
    - hard
    - nfsvers=4.1
  nfs:
    path: /data1/nfs-cluster-vol/jupyter/mldldb
    server: 192.168.0.100
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc-16g-jupyter-mldldb
spec:
  storageClassName: nfs-default-storageclass
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 16Gi

```
# KUBERNETES K8S DEV

```shell

# install basic dependencies

sudo apt-get install build-essential make openssl libssl-dev

```


```shell

# bootstrap and install container runtime 

sudo swapoff -a


(crontab -l 2>/dev/null; echo "@reboot /sbin/swapoff -a") | crontab - || true
sudo apt-get update -y

cat <<EOF | sudo tee /etc/modules-load.d/crio.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter


cat <<EOF | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

sudo sysctl --system


apt-get update
apt-get install -y software-properties-common curl

mkdir -p /etc/apt/keyrings

KUBERNETES_VERSION=v1.30
PROJECT_PATH=prerelease:/main

curl -fsSL https://pkgs.k8s.io/core:/stable:/$KUBERNETES_VERSION/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/$KUBERNETES_VERSION/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list

curl -fsSL https://pkgs.k8s.io/addons:/cri-o:/$PROJECT_PATH/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons:/cri-o:/$PROJECT_PATH/deb/ /" | tee /etc/apt/sources.list.d/cri-o.list

apt-get update

apt-get install -y cri-o 

systemctl daemon-reload
systemctl enable crio --now

systemctl start crio 


```


```shell

# install go



curl -OL https://golang.org/dl/go1.23.2.linux-amd64.tar.gz

sudo tar -C /usr/local -xvf go1.23.2.linux-amd64.tar.gz

rm -rf *.tar.gz

echo "export PATH=\$PATH:/usr/local/go/bin" >> $HOME/.profile


source ~/.profile

```




```shell


# install cfssl

go install github.com/cloudflare/cfssl/cmd/...@latest

```


```shell

# clone kubenernetes repo


git clone --filter=blob:none https://github.com/seantywork/kubernetes.git




```



```shell


# install etcd


./hack/install-etcd.sh

sudo nano ~/.profile

export KUBE_ROOT=/root/kubernetes
export GOPATH=/usr/local/go
export PATH=$PATH:$GOPATH/bin
export PATH="$KUBE_ROOT/third_party/etcd:${PATH}"


source ~/.profile

```


```shell

# modify and run


cat <<EOF > /tmp/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF


export CONTAINER_RUNTIME_ENDPOINT="unix:///run/crio/crio.sock"


make

# ./hack/local-up-cluster.sh

KUBELET_RESOLV_CONF="/tmp/resolv.conf" KUBELET_FLAGS="--cgroup-driver=systemd" ./hack/local-up-cluster.sh

```



```shell

export KUBECONFIG=/var/run/kubernetes/admin.kubeconfig

cd _output/local/bin/linux/amd64


./kubectl apply -f your.yaml
./kubectl get pods 


```


# KUBERNETES K8S


```shell
#!/bin/bash

set -euxo pipefail


######## wj


HOME="/root" 


sudo swapoff -a


(crontab -l 2>/dev/null; echo "@reboot /sbin/swapoff -a") | crontab - || true
sudo apt-get update -y



#OS="xUbuntu_20.04"

OS="$2"

#VERSION="1.25"

VERSION="$3"

cat <<EOF | sudo tee /etc/modules-load.d/crio.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter


cat <<EOF | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

sudo sysctl --system


cat <<EOF | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/ /
EOF
cat <<EOF | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable:cri-o:$VERSION.list
deb http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/ /
EOF

curl -L https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable:cri-o:$VERSION/$OS/Release.key | sudo apt-key --keyring /etc/apt/trusted.gpg.d/libcontainers.gpg add -
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/Release.key | sudo apt-key --keyring /etc/apt/trusted.gpg.d/libcontainers.gpg add -

sudo apt-get update
sudo apt-get install cri-o cri-o-runc crun -y

sudo systemctl daemon-reload
sudo systemctl enable crio --now

echo "Container runtime installed susccessfully"

sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl

sudo mkdir -p /etc/apt/keyrings


sudo curl -fsSL "https://pkgs.k8s.io/core:/stable:/v$VERSION/deb/Release.key" | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v$VERSION/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update -y
sudo apt-get install -y kubelet kubectl kubeadm
sudo apt-get update -y
sudo apt-get install -y jq



local_ip=$1
cat > /etc/default/kubelet << EOF
KUBELET_EXTRA_ARGS=--node-ip=$local_ip
EOF


MASTER_IP=$local_ip
LB_IP=$local_ip
IP_NO_DOT=$(echo "$local_ip" | sed "s/\./-/g")
PORT="3446"
NODENAME="$(hostname -s)"
NODENAME="lead-$NODENAME-$IP_NO_DOT-$(openssl rand -hex 8)"
POD_CIDR="10.10.0.0/16"

sudo kubeadm config images pull 

echo "Preflight Check Passed: Downloaded All Required Images"

sudo kubeadm init --apiserver-advertise-address=$MASTER_IP --apiserver-cert-extra-sans="$MASTER_IP,$LB_IP" --pod-network-cidr=$POD_CIDR --node-name "$NODENAME" --control-plane-endpoint "$LB_IP:$PORT" --ignore-preflight-errors Swap 
mkdir -p "$HOME"/.kube
sudo cp -i /etc/kubernetes/admin.conf "$HOME"/.kube/config
sudo chown "$(id -u)":"$(id -g)" "$HOME"/.kube/config

if [ -z ${INSTALL_CALICO+x} ]
then
  # cilium
  CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
  CLI_ARCH=amd64
  if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
  curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
  sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
  sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
  rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}

  cilium install --version 1.14.5

else
  # calico
  kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.0/manifests/calico.yaml
fi


kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml



kubectl label node $NODENAME ingress-ready=true 

```


```shell

#!/bin/bash


set -euxo pipefail



HOME="/root" 

sudo swapoff -a


(crontab -l 2>/dev/null; echo "@reboot /sbin/swapoff -a") | crontab - || true
sudo apt-get update -y



OS="$2"

VERSION="$3"


cat <<EOF | sudo tee /etc/modules-load.d/crio.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter


cat <<EOF | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

sudo sysctl --system


cat <<EOF | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/ /
EOF
cat <<EOF | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable:cri-o:$VERSION.list
deb http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/ /
EOF

curl -L https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable:cri-o:$VERSION/$OS/Release.key | sudo apt-key --keyring /etc/apt/trusted.gpg.d/libcontainers.gpg add -
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/Release.key | sudo apt-key --keyring /etc/apt/trusted.gpg.d/libcontainers.gpg add -

sudo apt-get update
sudo apt-get install cri-o cri-o-runc crun -y

sudo systemctl daemon-reload
sudo systemctl enable crio --now

echo "Container runtime installed susccessfully"


sudo apt-get update

sudo apt-get install -y apt-transport-https ca-certificates curl

sudo mkdir -p /etc/apt/keyrings

sudo curl -fsSL "https://pkgs.k8s.io/core:/stable:/v$VERSION/deb/Release.key" | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v$VERSION/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt-get update -y
sudo apt-get install -y kubelet kubectl kubeadm
sudo apt-get update -y
sudo apt-get install -y jq



local_ip=$1
cat > /etc/default/kubelet << EOF
KUBELET_EXTRA_ARGS=--node-ip=$local_ip
EOF
```

```shell

#!/bin/bash

sudo apt-get update

sudo apt-get install -y  haproxy 

```

```shell
#!/bin/bash

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

helm repo update

cd ./prom-grafana-charts/charts

helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack -f ./default-kube-prom-custom-value.yaml --version 42.2.0


```


```shell
#!/bin/bash

helm repo add nfs-subdir-external-provisioner https://kubernetes-sigs.github.io/nfs-subdir-external-provisioner/


helm install nfs-subdir-external-provisioner nfs-subdir-external-provisioner/nfs-subdir-external-provisioner \
    --set nfs.server=192.168.0.25 \
    --set nfs.path=/data


```

```shell
#!/bin/bash

helm repo add nvdp https://nvidia.github.io/k8s-device-plugin



helm repo update



helm upgrade -i nvdp nvdp/nvidia-device-plugin \

  --namespace nvidia-device-plugin \

  --create-namespace \

  --version 0.13.0





```

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-grafana

spec:
  rules:
  - host: grafana.mipllab.com
    http:
      paths:
        - path: /
          pathType: Prefix
          backend:
            service:
              name: kube-prometheus-stack-grafana
              port:
                number: 80

```


```shell
...

#---------------------------------------------------------------------
# main frontend which proxys to the backends
#---------------------------------------------------------------------
frontend kubernetes
    bind *:3446
    option tcplog
    mode tcp
    default_backend kube_master_nodes    


#---------------------------------------------------------------------
# static backend for serving up images, stylesheets and such
#---------------------------------------------------------------------
#backend static
#    balance     roundrobin
#    server      static 127.0.0.1:4331 check

#---------------------------------------------------------------------
# round robin balancing between the various backends
#---------------------------------------------------------------------
backend kube_master_nodes
    mode tcp
    balance     roundrobin
    option tcp-check
    server  -> check fall 3 rise 2



...




```


```shell

#!/bin/bash


ufw allow from 192.168.0.1/24 

ufw allow from 10.10.0.0/16



```


```shell

#!/bin/bash

firewall-cmd --permanent --add-port=3446/tcp

firewall-cmd --permanent --add-port=6443/tcp

firewall-cmd --permanent --add-port=2379-2380/tcp

firewall-cmd --permanent --add-port=10250/tcp

firewall-cmd --permanent --add-port=10259/tcp

firewall-cmd --permanent --add-port=10257/tcp

firewall-cmd --permanent --add-port=10250/tcp

firewall-cmd --permanent --add-port=30000-32767/tcp

firewall-cmd --permanent --add-port=80/tcp

firewall-cmd --permanent --add-port=443/tcp

firewall-cmd --zone=trusted --add-source=192.168.0.1/24 --permanent

firewall-cmd --zone=trusted --add-source=10.10.0.0/16 --permanent

```


```yaml

kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
  name: nfs-default-storageclass
provisioner: cluster.local/nfs-subdir-external-provisioner
reclaimPolicy: Delete
allowVolumeExpansion: true
volumeBindingMode: Immediate

```

```yaml

alertmanager:
  alertmanagerSpec:
    storage:
     volumeClaimTemplate:
       spec:
         storageClassName: nfs-default-storageclass
         accessModes: ["ReadWriteOnce"]
         resources:
           requests:
             storage: 4Gi
grafana:
  persistence:
    enabled: true
    type: pvc
    storageClassName: nfs-default-storageclass
    accessModes:
    - ReadWriteOnce
    size: 4Gi
prometheus:
  prometheusSpec:
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: nfs-default-storageclass
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 4Gi
```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: clusterdebugger
  labels:
    app: clusterdebugger
spec:
  type: ClusterIP
  ports:
  - port: 6700
    targetPort: 6700
    protocol: TCP
  selector:
    app: clusterdebugger
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: clusterdebugger
spec:
  selector:
    matchLabels:
      app: clusterdebugger
  replicas: 1
  template:
    metadata:
      labels:
        app: clusterdebugger
    spec:
      imagePullSecrets:
        - name: harbor-secret
      containers:
        - name: clusterdebugger
          image: harbor.mipllab.com/library/clusterdebugger
          imagePullPolicy: Always
          ports:
          - containerPort: 6700


```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: clusterdebuggergpu
  labels:
    app: clusterdebuggergpu
spec:
  type: ClusterIP
  ports:
  - port: 6700
    targetPort: 6700
    protocol: TCP
  selector:
    app: clusterdebuggergpu
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: clusterdebuggergpu
spec:
  selector:
    matchLabels:
      app: clusterdebuggergpu
  replicas: 1
  template:
    metadata:
      labels:
        app: clusterdebuggergpu
    spec:
      nodeSelector:
        gpu-ready1: ready
      imagePullSecrets:
        - name: harbor-secret
      containers:
        - name: clusterdebuggergpu
          image: harbor.mipllab.com/library/clusterdebugger
          resources:
            limits:
              nvidia.com/gpu: 1
          imagePullPolicy: Always
          ports:
          - containerPort: 6700


```


```shell
#!/bin/bash


USER=tomcat # customizable
mkdir -p /etc/kubernetes/pki/etcd
mv /home/${USER}/ca.crt /etc/kubernetes/pki/
mv /home/${USER}/ca.key /etc/kubernetes/pki/
mv /home/${USER}/sa.pub /etc/kubernetes/pki/
mv /home/${USER}/sa.key /etc/kubernetes/pki/
mv /home/${USER}/front-proxy-ca.crt /etc/kubernetes/pki/
mv /home/${USER}/front-proxy-ca.key /etc/kubernetes/pki/
mv /home/${USER}/etcd-ca.crt /etc/kubernetes/pki/etcd/ca.crt
mv /home/${USER}/etcd-ca.key /etc/kubernetes/pki/etcd/ca.key
mv /home/${USER}/admin.conf /etc/kubernetes/admin.conf



```

```shell
#!/bin/bash

USER=tomcat # customizable
# Set the control_plane_ips to all other master node ips or hostnames
CONTROL_PLANE_IPS="192.168.0.102 192.168.0.103"
for host in ${CONTROL_PLANE_IPS}; do
    scp /etc/kubernetes/pki/ca.crt "${USER}"@$host:
    scp /etc/kubernetes/pki/ca.key "${USER}"@$host:
    scp /etc/kubernetes/pki/sa.key "${USER}"@$host:
    scp /etc/kubernetes/pki/sa.pub "${USER}"@$host:
    scp /etc/kubernetes/pki/front-proxy-ca.crt "${USER}"@$host:
    scp /etc/kubernetes/pki/front-proxy-ca.key "${USER}"@$host:
    scp /etc/kubernetes/pki/etcd/ca.crt "${USER}"@$host:etcd-ca.crt
    scp /etc/kubernetes/pki/etcd/ca.key "${USER}"@$host:etcd-ca.key
    scp /etc/kubernetes/admin.conf "${USER}"@$host:
done



```

# KAFKA

```shell
#!/bin/bash



helm repo add bitnami https://charts.bitnami.com/bitnami




helm install zookeeper bitnami/zookeeper --set replicaCount=1 --set auth.enabled=false --set allowAnonymousLogin=true



helm install kafka bitnami/kafka --set zookeeper.enabled=false --set replicaCount=1 --set externalZookeeper.servers=ZOOKEEPER-SERVICE-NAME


```
# KIBANA


```yaml

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-kibana
  annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "0"

spec:
  rules:
  - host: kibana.usagecorpus.com
    http:
      paths:
        - path: /
          pathType: Prefix
          backend:
            service:
              name: kibana
              port:
                number: 5601



```

```yaml

apiVersion: v1
kind: Service
metadata:
  name: kibana
  labels:
    app: kibana
spec:
  type: ClusterIP
  ports:
  - port: 5601
    targetPort: 5601
    protocol: TCP
  selector:
    app: kibana
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kibana
spec:
  selector:
    matchLabels:
      app: kibana
  replicas: 1
  template:
    metadata:
      labels:
        app: kibana
    spec:
      imagePullSecrets:
        - name: harbor-secret
      containers:
        - name: kibana
          image: seantywork/kibana
          imagePullPolicy: Always
          ports:
          - containerPort: 5601



```


```yaml

version: "3"
services:
    kibana:
        build: ./kibana
        container_name: kibana
        restart: always
        ports:
            - 5601:5601
        networks:
            - network1

networks:
    network1:
        name: elastic_default
        external: true
```

```shell
FROM kibana:8.5.3

ENV ELASTICSEARCH_USERNAME="kibana_system"
ENV ELASTICSEARCH_PASSWORD="estest"
ENV ELASTICSEARCH_HOSTS=http://elasticsearch:9200
ENV XPACK_MONITORING_ENABLED=true
ENV XPACK_MONITORING_COLLECTION_ENABLED=true
ENV XPACK_SECURITY_ENABLED=true

EXPOSE 5601


```

# MONGO DB

```yaml
version: "3"
services:
        mongodb:
                build: ./mdb
                container_name: mongodb
                ports:
                        - 27017:27017
                volumes:
                        - ./mdb/data:/data/db


```


```shell
FROM mongo:4.4.19-rc1

ENV MONGO_INITDB_ROOT_USERNAME root
ENV MONGO_INITDB_ROOT_PASSWORD youdonthavetoknow

EXPOSE 27017

```

# OPENSTACK


```shell

# devstack

sudo useradd -s /bin/bash -d /opt/stack -m stack
echo "stack ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/stack
sudo -u stack -i

git clone https://opendev.org/openstack/devstack
cd devstack

# local.conf

[[local|localrc]]
ADMIN_PASSWORD=openstack
DATABASE_PASSWORD=openstack
RABBIT_PASSWORD=openstack
SERVICE_PASSWORD=openstack
HOST_IP=$IP_ADDR_OF_VM

./stack.sh

user: admin
password: openstack

```





# NFS

```shell

#!/bin/bash

sudo dnf install nfs-utils



sudo systemctl start nfs-server.service


sudo systemctl enable --now nfs-server.service


## /etc/exports

## exportfs -a


```

```shell
#!/bin/bash

apt update

apt install -y nfs-kernel-server

apt install -y nfs-common

apt install -y jq

mkdir -p /kw_data

chown -R root:root /kw_data

chmod -R 777 /kw_data



local_ip=$1

IP=$local_ip

cat << EOF > /etc/exports

/kw_data $IP/24(rw,sync,no_subtree_check,no_root_squash) 10.10.0.0/16(rw,sync,no_subtree_check,no_root_squash)

EOF

exportfs -a

systemctl restart nfs-kernel-server

```


# NGINX CONF

```shell

user www-data;
worker_processes auto;
pid /run/nginx.pid;
#include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        reset_timedout_connection on;
        client_body_timeout 10;
        send_timeout 2;

        keepalive_timeout 30;
        keepalive_requests 100000;

        client_max_body_size 10G;


        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        #gzip on;

        #gzip_comp_level  2;
        #gzip_min_length  1000;
        #gzip_proxied     expired no-cache no-store private auth;
        #gzip_types       text/plain application/x-javascript text/xml text/css application/xml;

        include /etc/nginx/conf.d/*.conf;

}
```

```shell



server
{
        
        listen 80;

        server_name  exhibit-nginx.usagecorpus.com;

        location / {
             add_header Content-Type text/plain;
             return 200 'okay';           

        }


}

```

```shell

upstream  EXNGINX{
        ip_hash;
        #least_conn;

        server  127.0.0.1:8000;
        server  127.0.0.1:8001;

}

server
{
        listen       80;
        server_name      exhibit-nginx.usagecorpus.com;
        return 301 https://$host$request_uri;
}



server
{
        
        server_name  exhibit-nginx.usagecorpus.com;

        location / {
             #add_header Content-Type text/plain;
             #return 200 'okay';           

             proxy_pass http://EXNGINX;
             proxy_set_header X-Real-IP $remote_addr;
             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
             proxy_set_header X-Forwarded-For $remote_addr;
             proxy_set_header X-Forwarded-Proto $scheme;
             proxy_set_header Host $http_host;

             proxy_read_timeout 300s;
             proxy_connect_timeout 75s;
             
             proxy_buffering off;
             proxy_request_buffering off;

             proxy_http_version 1.1;
             proxy_set_header   Upgrade $http_upgrade;
             proxy_set_header   Connection "upgrade";
        }







    #listen 80; # managed by Certbot

    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/exhibit-nginx.usagecorpus.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/exhibit-nginx.usagecorpus.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

}
```

```shell

# add server without restart

sudo nginx -s reload

```


```shell
#!/bin/bash


while true; do nc -l 0.0.0.0 8000 < resp; done


```


# CMAKELISTS TXT CMAKE

```shell

cd $PROJECT_DIR

mkdir -p build

cd build

cmake ..

make

# blah blah after that


```
```shell
# build lib


cmake_minimum_required(VERSION 3.2)
project(dynamiclink_print)
set(CMAKE_BUILD_TYPE Release)

include_directories(include)

set(SOURCES src/crazything.cc)


# target lib for .so
add_library(crazything SHARED ${SOURCES})
# target lib for .a
add_library(something STATIC ${SOURCES})

# for installing lib: sudo make install...
install(TARGETS crazything DESTINATION /usr/lib)


```


```shell
# build target

# min ver
cmake_minimum_required(VERSION 3.2)
# project name
project (main_lib_print)


# include
include_directories(
    ../2_staticlink_print/include
    ../3_dynamiclink_print/include
    )

# set var
set ( PROJECT_LINK_LIBS libsomething.a libcrazything.so)

# static or dynamic link dirs
link_directories( 
    ../2_staticlink_print/build
    ../3_dynamiclink_print/build 
    )


# target bin
add_executable(main.out main.cc)

# linking to target bin
target_link_libraries(main.out ${PROJECT_LINK_LIBS})

```

```shell

# include another one

include(another/cmakelists.txt)



# source all
file(
  GLOB somefile
  "${SRC_DIR}/*.c"
)

# -pthread

Threads::Threads

# export (when included in another CMakeLists.txt)
install(
  TARGETS thethinghere
  EXPORT thethinghere
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
)

install(
  EXPORT thethinghere
  DESTINATION lib
  FILE agvcancomm-Config.cmake
)



```


# JENKINSFILE


```shell

pipeline{

    agent any

        environment {

            // Target Path

            TARGET_PATH="/home/target"
            TARGET_PREFIX="target_"

            // Preparation Stage

            GIT_ADDR="https://${GIT_ID}:${GIT_PW}@github.com/seantywork/nothing.git"
            GIT_BRANCH="main"
            
            // Build Stage

            REG_ADDR="docker.io -u ${REG_ID} -p ${REG_PW}"
            IMG_1="${TARGET_PREFIX}nothing"
            TAG_1="docker.io/seantywork/nothing"


            // Deployment Stage

            DEPLOYMENT_NODE="${DEPLOYMENT_NODE}"

            APP_PATH_1="${TARGET_PATH}/k8s/app.yaml"


            UPDATE_1="deployment/nothing"


            
            // ********* Safe Scripts **********

            // stage Preparation_checkSafe
            // --> USAGE: ${SAFE_PREP} ${TARGET_PATH} 
            SAFE_PREP="/home/safe_preparation"

            // stage Termination_checkSafe
            // --> USAGE: ${SAFE_TERM} ${TAG_1} ${TAG_2} ...
            SAFE_TERM="/home/safe_termination"


        }

    stages{



        stage ('Preparation'){

            steps {

                sh ''' #!/bin/bash

                    mkdir -p ${TARGET_PATH}

                    git -C ${TARGET_PATH} init

                    git -C ${TARGET_PATH} pull ${GIT_ADDR} ${GIT_BRANCH}

                '''

            }

        }

        stage ('Preparation-safety-check'){

            steps {

                sh ''' #!/bin/bash

                    ${SAFE_PREP} ${TARGET_PATH} 

                '''

            }

        }

        stage ('Build'){

            steps {

                sh ''' #!/bin/bash

                    docker login ${REG_ADDR}

                    docker-compose -f "${TARGET_PATH}/docker-compose.yaml" up -d --build

                    docker-compose -f "${TARGET_PATH}/docker-compose.yaml" down

                    docker tag ${IMG_1} ${TAG_1}

                    docker push ${TAG_1}

                '''

            }

        }

        stage ('Deployment'){

            steps {

                sh ''' #!/bin/bash

                    scp ${APP_PATH_1} "${DEPLOYMENT_NODE}:/home/src"

                    ssh ${DEPLOYMENT_NODE} "kubectl -n operation apply -f app.yaml"

                    ssh ${DEPLOYMENT_NODE} "kubectl -n operatioin rollout restart ${UPDATE_1}"

                    ssh ${DEPLOYMENT_NODE} "rm ./app.yaml"

                '''
            }

        }

        stage ('Termination'){

            steps {

                sh ''' #!/bin/bash

                    rm -rf ${TARGET_PATH}

                '''


            }

        }

        stage ('Termination-safety-check'){

            steps {

                sh ''' #!/bin/bash

                    ${SAFE_TERM} ${TAG_1} 

                '''

            }


        }


    }
}


```



# GITHUB WORKFLOW

```yaml

name: self hosted runner

on :
  push:
    branches: [ main ]

jobs:

  uc_self_hosted_build:
    runs-on: self-hosted
    steps: 
      - run: mkdir -p /root/uc
      - run: git -C /root/uc init
      - run: git -C /root/uc pull https://github.com/seantywork/uc.git 
      - run: docker-compose -f /root/uc/docker-compose.yaml up -d --build
      - run: docker-compose -f /root/uc/docker-compose.yaml down
      - run: docker tag uc_traffic seantywork/traffic
      - run: docker tag uc_web seantywork/web
      - run: docker tag uc_db seantywork/db
      - run: docker push seantywork/traffic
      - run: docker push seantywork/web
      - run: docker push seantywork/db
      - run: rm -r /root/uc

  uc_self_hosted_deployment:
    needs: uc_self_hosted_build
    runs-on: self-hosted
    steps:
      - run: ssh $SSH_XY "git -C /home/seantywork/uc pull "
      - run: ssh $SSH_XY "kind delete cluster --name kindcluster"
      - run: ssh $SSH_XY "kind create cluster --name kindcluster --config /home/seantywork/uc/k8s/kindcluster.yaml --image=kindest/node:v1.27.2"
      - run: ssh $SSH_XY "kubectl create namespace uc"
      - run: ssh $SSH_XY "kubectl create secret generic docker-secret --from-file=.dockerconfigjson=/root/.docker/config.json --type=kubernetes.io/dockerconfigjson -n uc"
      - run: ssh $SSH_XY "kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml"
      - run: sleep 3
      - run: echo "waiting...1"
      - run: sleep 3
      - run: echo "waiting...2"
      - run: sleep 3
      - run: echo "waiting...3"
      - run: sleep 3
      - run: echo "waiting...4"
      - run: sleep 3
      - run: echo "waiting...5"
      - run: ssh $SSH_XY "kubectl -n uc apply -f /home/seantywork/uc/k8s/app.yaml"
 
  uc_self_hosted_service:
    needs: uc_self_hosted_deployment
    runs-on: self-hosted
    steps:
      - run: sleep 3
      - run: echo "waiting...1"
      - run: sleep 3
      - run: echo "waiting...2"
      - run: sleep 3
      - run: echo "waiting...3"
      - run: sleep 3
      - run: echo "waiting...4"
      - run: sleep 3
      - run: echo "waiting...5"
      - run: ssh $SSH_XY "kubectl -n uc apply -f /home/seantywork/uc/k8s/ingress.yaml"
  

```


# REDIS

```yaml
version: "3"

services:

    redis:
      build: ./redis
      container_name: redis
      volumes:
        - ./redis/data:/var/lib/redis/data
        - ./redis/redis.conf:/usr/local/etc/redis/redis.conf
      ports:
        - "6379:6379"


```


```shell

FROM redis:7.0.8

EXPOSE 6379

CMD ["/bin/sh","-c","redis-server","--requirepass","youdonthavetoknow"]


```


```shell

port              6379
daemonize         yes
save              60 1
bind              0.0.0.0
tcp-keepalive     300
dbfilename        dump.rdb
dir               ./
rdbcompression    yes

```


# REMOTE DESKTOP

```shell

# remote server

sudo apt install xrdp -y

sudo systemctl restart xrdp


# client

sudo apt install remmina remmina-plugin-vnc



```

# GRPC SET UP


```shell
# install

export MY_gRPC_DIR=$HOME/.local

mkdir -p $MY_gRPC_DIR

export PATH="$MY_gRPC_DIR/bin:$PATH"

# cmake version should be 3.8+


sudo apt install -y build-essential autoconf libtool pkg-config

git clone --recurse-submodules -b v1.60.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc


cd grpc
mkdir -p cmake/build
pushd cmake/build
cmake -DgRPC_INSTALL=ON \
      -DgRPC_BUILD_TESTS=OFF \
      -DCMAKE_INSTALL_PREFIX=$MY_gRPC_DIR \
      ../..
make -j 4
sudo make install
popd


```


```shell

# build

# src CMakeLists.txt and common.cmake update

export MY_gRPC_DIR=$HOME/.local

mkdir -p build

cd build && cmake -DCMAKE_PREFIX_PATH=$MY_gRPC_DIR ..

make -j 4


```


# ROS 2

```shell

# on ubuntu 22.04 ros2 humble hawksbill

# takes up about 2G disk space

locale  # check for UTF-8

sudo apt update && sudo apt install locales
sudo locale-gen en_US en_US.UTF-8
sudo update-locale LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8
export LANG=en_US.UTF-8

locale  # verify settings



sudo apt install software-properties-common
sudo add-apt-repository universe


sudo apt update && sudo apt install curl -y
sudo curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key -o /usr/share/keyrings/ros-archive-keyring.gpg


echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] http://packages.ros.org/ros2/ubuntu $(. /etc/os-release && echo $UBUNTU_CODENAME) main" | sudo tee /etc/apt/sources.list.d/ros2.list > /dev/null




sudo apt update


sudo apt upgrade


sudo apt install ros-humble-desktop


sudo apt install ros-humble-ros-base


sudo apt install ros-dev-tools



source /opt/ros/humble/setup.bash


# check if installation is succeful


# terminal 1

source /opt/ros/humble/setup.bash
ros2 run demo_nodes_cpp talker


# terminal 2

source /opt/ros/humble/setup.bash
ros2 run demo_nodes_py listener


```


```shell

# cartographer

ros2 pkg list |grep cartographer

# if none

sudo apt install ros-$ROS_DISTRO-cartographer -y

# turtlebot3

sudo apt install ros-$ROS_DISTRO-turtlebot3* -y

# simulation

source /opt/ros/humble/setup.bash

export TURTLEBOT3_MODEL=burger

export GAZEBO_MODEL_PATH=`ros2 pkg \
prefix turtlebot3_gazebo`/share/turtlebot3_gazebo/models/


ros2 launch turtlebot3_gazebo turtlebot3_world.launch.py

# troubleshoot
# not sure if effective?
gazebo -s libgazebo_ros_init.so -s libgazebo_ros_factory.so myworld.world


# on terminal 2 remote pc: teleoperation node

source /opt/ros/humble/setup.bash

ros2 run turtlebot3_teleop teleop_keyboard

# on terminal 3 remote pc: cartographer

source /opt/ros/humble/setup.bash

ros2 launch turtlebot3_cartographer \
cartographer.launch.py \
use_sim_time:=True

```


```shell

# real

# on turtlebot3 do below

source .bashrc

cd turtlebot3_ws

#Set up ROS_DOMAIN_ID

export ROS_DOMAIN_ID="Your Number"

# e.g. export ROS_DOMAIN_ID=11

source install/setup.bash

ros2 launch turtlebot3_bringup robot.launch.py

# on terminal2 : teleoperation node


source /opt/ros/humble/setup.bash

export ROS_DOMAIN_ID="Your Number"
# e.g. export ROS_DOMAIN_ID=11

ros2 run turtlebot3_teleop teleop_keyboard


# on terminal3 : cartoprapher



source /opt/ros/humble/setup.bash

export ROS_DOMAIN_ID="Your Number"
# e.g. export ROS_DOMAIN_ID=11

ros2 run cartographer_ros occupancy_grid_node -resolution 0.05\
-publish_period_sec 1.0

ros2 run cartographer_ros cartographer_node\
-configuration_directory]\ 
install/turtlebot3_cartographer/share/turtlebot3_cartographer\
/config -configuration_basename turtlebot3_lds_2d.lua


```

# ROS API

```shell
# term1

mkdir -p ros2_ws/src


source /opt/ros/humble/setup.bash

# git clone https://github.com/ros/ros_tutorials.git -b humble

# term1 dependency at ros2_ws

rosdep install -i --from-path src --rosdistro humble -y

# term1 build at ros2_ws

colcon build --symlink-install

# term2

source /opt/ros/humble/setup.bash

# term2 at ros2_ws

source install/local_setup.bash

```

```shell

# term1

# package dev

source /opt/ros/humble/setup.bash

# package dec at ros2_ws/src

ros2 pkg create --build-type ament_cmake --node-name $NODE_NAME $PKG_NAME

# source goes to ros2_ws/src/$PKG_NAME/src

# package.xml, CMakeLists.txt update

# install dependency at ros2_ws

rosdep install -i --from-path src --rosdistro humble -y

# package build at ros2_ws

colcon build --symlink-install --packages-select $PKG_NAME



# term2

source /opt/ros/humble/setup.bash

# term2 at ros2_ws

source install/local_setup.bash

# run

ros2 run $PKG_NAME $NODE_NAME



```
# ROS COLCON BUILD LAUNCH

```shell
# term 1

source /opt/ros/directory/setup.bash

colcon build --symlink-install

```

```shell
# term 2

source install/setup.bash

ros2 launch $PAKCAGE_NAME $LAUNCHFILE_NAME


```


# ROS DOCKER

```shell

# pyslam v2

nvidiactk

# config.sh work dir 

build.sh <NAME>

xhost +

run.sh <NAME>

# $DISPLAY ?



```


# CAN NETWORK

```shell

# using gpio

sudo apt-get install busybox


# register up for a test

sudo busybox devmem 0x0c303000 32 0x0000C400
sudo busybox devmem 0x0c303008 32 0x0000C458
sudo busybox devmem 0x0c303010 32 0x0000C400
sudo busybox devmem 0x0c303018 32 0x0000C458


sudo modprobe can
sudo modprobe can_raw
sudo modprobe mttcan


# each second line optional?

sudo ip link set can0 type can bitrate 500000 \
    dbitrate 2000000 berr-reporting on fd on
sudo ip link set can1 type can bitrate 500000 \
    dbitrate 2000000 berr-reporting on fd on


sudo ip link set up can0
sudo ip link set up can1


# cron the sh file at reboot

```
```shell

# vcan

sudo modprobe vcan

ip link add dev vcan0 type vcan

ip link set up vcan0

```

```shell
# can utils

sudo apt-get install can-utils

# send to if with id
cansend vcan0 101#41424344

# dump all incoming data

candump -t Absolute vcan0

# send random frame continuously

cangen vcan0


```

# CANOPEN

```shell

git clone https://github.com/CANopenNode/CANopenLinux.git
cd CANopenLinux
git submodule init
git submodule update


sudo modprobe can
sudo modprobe can_raw
sudo modprobe mttcan




sudo ip link set can0 type can bitrate 500000 \
    dbitrate 2000000 berr-reporting on fd on


sudo ip link set up can0

cd CANopenLinux

make

sudo make install

canopend --help

# send SDO, PDO according to the motor driver vendor manual

```


# MQTT

```shell
# docker compose

version: "3.7"

services:
  mosquitto:
    image: eclipse-mosquitto
    container_name: mosquitto
    restart: unless-stopped
    ports:
      - "1883:1883"
      - "9001:9001"
    volumes:
      - ./mosquitto:/etc/mosquitto
      - ./mosquitto/mosquitto.conf:/mosquitto/config/mosquitto.conf

```


```shell

# volume config

listener 1883
allow_anonymous true
# password_file /etc/mosquitto/passwd

```

# RASPBERRY PI

```shell
# gpio pins for rpi 4

| #  |           | PIN  |    |    | PIN  |          | #  |
|----|-----------|------|----|----|------|----------|----|
| 1  | 3v3 Power | `1`  | 🟧 | 🔴 | `2`  | 5v Power | 20 |
| 2  | GPIO 2    | `3`  | 🔵 | 🔴 | `4`  | 5v Power | 19 |
| 3  | GPIO 3    | `5`  | 🔵 | ⚫ | `6`  | *Ground* | 18 |
| 4  | GPIO 4    | `7`  | 🟢 | 🟣 | `8`  | GPIO 14  | 17 |
| 5  | *Ground*  | `9`  | ⚫ | 🟣 | `10` | GPIO 15  | 16 |
| 6  | GPIO 17   | `11` | 🟢 | 🟤 | `12` | GPIO 18  | 15 |
| 7  | GPIO 27   | `13` | 🟢 | ⚫ | `14` | *Ground* | 14 |
| 8  | GPIO 22   | `15` | 🟢 | 🟢 | `16` | GPIO 23  | 13 |
| 9  | 3v3 Power | `17` | 🟠 | 🟢 | `18` | GPIO 24  | 12 |
| 10 | GPIO 10   | `19` | 🟡 | ⚫ | `20` | *Ground* | 11 |
| 11 | GPIO 9    | `21` | 🟡 | 🟢 | `22` | GPIO 25  | 10 |
| 12 | GPIO 11   | `23` | 🟡 | 🟡 | `24` | GPIO 8   | 9  |
| 13 | *Ground*  | `25` | ⚫ | 🟡 | `26` | GPIO 7   | 8  |
| 14 | GPIO 0    | `27` | 🔵 | 🔵 | `28` | GPIO 1   | 7  |
| 15 | GPIO 5    | `29` | 🟢 | ⚫ | `30` | *Ground* | 6  |
| 16 | GPIO 6    | `31` | 🟢 | 🟢 | `32` | GPIO 12  | 5  |
| 17 | GPIO 13   | `33` | 🟢 | ⚫ | `34` | *Ground* | 4  |
| 18 | GPIO 19   | `35` | 🟤 | 🟢 | `36` | GPIO 16  | 3  |
| 19 | GPIO 26   | `37` | 🟢 | 🟤 | `38` | GPIO 20  | 2  |
| 20 | *Ground*  | `39` | ⚫ | 🟤 | `40` | GPIO 21  | 1  |

**Legend:**

* 🟢 GPIO (General Purpose IO)
* 🟡 SPI (Serial Peripheral Interface)
* 🔵 I2C (Inter-integrated Circuit)
* 🟣 UART (Universal Asyncronous)
* 🟤 PCM (Pulse Code Modulation)
* ⚫ Ground
* 🔴 5v (Power)
* 🟠 3.3v (Power)

```


```shell

# get real pin number (device tree)


cat /sys/kernel/debug/gpio

```

```shell

# pgpio

# install pigpio
wget https://github.com/joan2937/pigpio/archive/master.zip
unzip master.zip
cd pigpio-master
make
sudo make install

# wiringpi

sudo apt install wiringpi

# ir receiver

# S
# > OUT
# > POWER
# > GND
# -

# OUT to GPIO 4
# POWER to PIN 1
# GND to PIN 9
```
```shell
# lirc

# ir transmitter

# > DAT
# > VCC
# > GND

# DAT to GPIO 23
# VCC to PIN 2
# GND to PIN 20

# install lirc

sudo apt-get update 

sudo apt-get install lirc -y


```shell
# on xU22.04
# /boot/firmware/config.txt
# below last [all]

[all]
...
dtoverlay=gpio-ir,gpio_pin=4
dtoverlay=gpio-ir-tx,gpio_pin=23
...

# 4 receive < in

# 23 transmit > out
```

```shell
# /etc/lirc/hardware.conf

LIRCD_ARGS="--uinput --listen"
LOAD_MODULES=true
DRIVER="default"
DEVICE="/dev/lirc0"
MODULES="lirc_rpi"

# /etc/lirc/lirc_options.conf

#driver         = devinput
#device         = auto
driver          = default
device          = /dev/lirc0
```
```shell

# check incoming infrared signal

sudo systemctl stop lircd

sudo mode2 -m -d /dev/lirc1 > *.lirc.conf

# *.lirc.conf format

begin remote

  name LG_AC
  flags RAW_CODES|CONST_LENGTH
  eps 30
  aeps 100

  gap 513079

      begin raw_codes

  name AC_ON

     3044     9814      495     1569      465      548
      469      548      469      550      467     1592
      441      549      525      496      494      520
      466      551      469      548      469      550
      467      548      465      577      468      549
      466      552      465      550      466      550
      450     1612      468     1566      443     1620
      418      571      467      550      520      497
      498      519      494      523      467     1620
      420     1614      442     1619      464   

  name AC_OFF

     3075     9815      493     1593      442      548
      470      549      470      546      468     1591
      441      575      470      547      467      550
      467     1595      439     1594      439      553
      468      550      465      573      466      551
      444      573      443      574      446      570
      444      572      444      573      443      574
      444      572      444     1617      440      556
      462     1593      445      572      445      575
      468      572      444     1617      418   

      end raw_codes

end remote


# cp

sudo cp lgac.lirc.conf /etc/lirc/lircd.conf.d/


# mv 

sudo mv /etc/lirc/lircd.conf.d/devinput.lircd.conf /etc/lirc/lircd.conf.d/devinput.lircd.conf.bak

# reboot

# list

sudo irsend LIST LG_AC ""

# send

sudo irsend SEND_ONCE LG_AC AC_ON

```



# JETSON XAVIER NX

```shell

# first flash

# recovery mode

# check if recovery mode

lsusb 

# get jetson linux bsp and rootfs

# 35.4.1 (ubuntu20)

# https://developer.nvidia.com/embedded/jetson-linux-r3541

# un bzip2 un tar both and get the rootfs using sudo tar into BSP/rootfs

sudo ./apply_binaries.sh

sudo ./nvautoflash.sh

# now on jetson

fdisk /dev/nvme0n

mkfs.ext4 /dev/nvme0np1


# copy to volume and then switch rootfs when booting

sudo mount /dev/nvme0n1p1 /mnt

sudo rsync -axHAWX --numeric-ids --info=progress2 --exclude={"/dev/","/proc/","/sys/","/tmp/","/run/","/mnt/","/media/*","/lost+found"} / /mnt


sudo cp setssdroot.service /etc/systemd/system
sudo cp setssdroot.sh /sbin
sudo chmod 777 /sbin/setssdroot.sh
systemctl daemon-reload
sudo systemctl enable setssdroot.service


sudo cp /etc/systemd/system/setssdroot.service /mnt/etc/systemd/system/setssdroot.service
sudo cp /sbin/setssdroot.sh /mnt/sbin/setssdroot.sh


sudo touch /etc/setssdroot.conf

```

```shell
# setssdroot.service

[Unit]
Description=Change rootfs to SSD in M.2 key M slot (nvme0n1p1)
DefaultDependencies=no
Conflicts=shutdown.target
After=systemd-remount-fs.service
Before=local-fs-pre.target local-fs.target shutdown.target
Wants=local-fs-pre.target
ConditionPathExists=/dev/nvme0n1p1
ConditionPathExists=/etc/setssdroot.conf
ConditionVirtualization=!container
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/setssdroot.sh
[Install]
WantedBy=default.target

```

```shell
# setssdroot.sh
#!/bin/sh
NVME_DRIVE="/dev/nvme0n1p1"
CHROOT_PATH="/nvmeroot"

INITBIN=/lib/systemd/systemd
EXT4_OPT="-o defaults -o errors=remount-ro -o discard"

modprobe ext4

mkdir -p ${CHROOT_PATH}
mount -t ext4 ${EXT4_OPT} ${NVME_DRIVE} ${CHROOT_PATH}

cd ${CHROOT_PATH}
/bin/systemctl --no-block switch-root ${CHROOT_PATH}
```

```shell

# install jetpack

sudo apt update
sudo apt install nvidia-jetpack


```


# VIDEO LIVE STREAM FFMPEG GSTREAMER RTMP NGINX

```shell

sudo apt install -y ffmpeg v4l-utils

sudo apt install libnginx-mod-rtmp


```

```shell

# gstreamer

apt-get install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libgstreamer-plugins-bad1.0-dev gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly gstreamer1.0-libav gstreamer1.0-tools gstreamer1.0-x gstreamer1.0-alsa gstreamer1.0-gl gstreamer1.0-gtk3 gstreamer1.0-qt5 gstreamer1.0-pulseaudio

# gstreamer arm

 + gstreamer1.0-libcamera


```


```shell
# /etc/nginx/nginx.conf

# for ssl
stream{

        upstream RTMP_SERVER {
                server 192.168.0.32:1936;
        }


        server {
                listen 1935 ssl;
                proxy_pass RTMP_SERVER;
                ssl_certificate /etc/letsencrypt/live/feebdaed.xyz/fullchain.pem;
                ssl_certificate_key /etc/letsencrypt/live/feebdaed.xyz/privkey.pem;
        }
}

rtmp {
        server {
                listen 1936;
                allow publish 192.168.0.32;

                # allow publish feebdaed.xyz

                application live {
                        live on;
                        interleave on;
                        record off;
                        hls on;
                        hls_path /tmp/hls;
                        hls_fragment 15s;

                        # external auth server
                        on_publish http://localhost:5000/auth;
                        notify_method get;

                }
        }
}

# /etc/nginx/conf.d/hls.conf

server
{

        listen      8080 ssl;
        ssl_certificate /etc/letsencrypt/live/feebdaed.xyz/fullchain.pem; # managed by Certbot
        ssl_certificate_key /etc/letsencrypt/live/feebdaed.xyz/privkey.pem; # managed by Certbot
        include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
        ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

        location /hls {
            types {
                application/vnd.apple.mpegurl m3u8;
                video/mp2t ts;
            }
            root /tmp;
            add_header Cache-Control no-cache;

            # for file:// testing only
            add_header Access-Control-Allow-Origin *;

        }
}


```


```shell

# stream to rtmp server


ffmpeg -f v4l2 -i /dev/video0 \
  -f alsa -i hw:0,0 \
  -c:v libx264 -pix_fmt yuv420p -framerate 15 -g 30 -b:v 500k \
  -c:a aac -b:a 128k -ar 44100 -ac 2 \
  -f flv -flvflags no_duration_filesize \
  "rtmps://$HOST/live/MyWebCam?puser=$PUSER"

#  -preset ultrafast -tune zerolatency                             \


```


```shell
# stream to rtp server


ffmpeg -i /dev/video0 -r 24 -video_size 640x480 -vcodec libvpx -cpu-used 5 -deadline 1 -g 10 -error-resilient 1 -auto-alt-ref 1 -f rtp 'rtp://127.0.0.1:5004?pkt_size=1200'


```

```shell

# stream to rtmp server

gst-launch-1.0 -e v4l2src device=/dev/video0 ! queue ! videoconvert ! videoscale ! video/x-raw,width=960,height=720 ! x264enc speed-preset=ultrafast tune=zerolatency key-int-max=20 ! flvmux streamable=true ! queue ! rtmpsink location='rtmp://localhost:8084/publish/foobar'

# youtube

gst-launch-1.0 v4l2src device=/dev/video0 ! queue ! videoconvert ! videoscale ! video/x-raw,width=640,height=480 ! x264enc speed-preset=ultrafast tune=zerolatency key-int-max=20 ! flvmux streamable=true name=mux ! queue ! rtmpsink location='rtmp://a.rtmp.youtube.com/live2/qbm8-a0dq-x7z5-hks7-3m6w' audiotestsrc is-live=true ! lamemp3enc ! mpegaudioparse ! mux.

```

# ETHERCAT

```shell

# 2.8

# download linuxcnc image

# https://linuxcnc.org/iso/

# unzip and flash image

dd sudo dd if=2021-01-20-linuxcnc-pi4.img of=/dev/sda bs=1M status=progress

# modify if needed as follow


```

```shell
# if needed on pi3

[pi4]
kernel=vmlinuz-4.19.71-rt24-v7l+
force_turbo=1

to this:

[pi3b]
kernel=vmlinuz-4.19.71-rt24-v7l+
force_turbo=1

# free prevention

# add to cmdline.txt

dwc_otg.fiq_fsm_enable=0 dwc_otg.fiq_enable=0 dwc_otg.nak_holdoff=0


```

```shell
# on newly installed rpi

uname -a
sudo apt update
sudo apt upgrade
sudo reboot


# etherlab master

uname -a
apt-cache search 4.19.71
sudo apt install linux-headers-4.19.71-rt24-v7l

sudo apt install mercurial build-essential automake tree dkms bison flex


git clone github.com/icshwi/etherlabmaster
cd etherlabmaster
make init
echo "ENABLE_CYCLES = NO" > configure/CONFIG_OPTIONS.local
make build
make install
echo "ETHERCAT_MASTER0=eth0" > ethercatmaster.local
make dkms_add
make dkms_build
make dkms_install
make setup

sudo mkdir -p /usr/include/linuxcnc
sudo ln -s /opt/etherlab/include/*.h /usr/include/linuxcnc/
sudo ln -s /opt/etherlab/lib/lib* /usr/lib/

sudo reboot


# linuxcnc ethercat

sudo apt install linuxcnc-uspace-dev

git clone github.com/sittner/linuxcnc-ethercat
cd linuxcnc-ethercat
make configure
make
sudo make install

linuxcnc
```

```shell
# 2.9
# download linuxcnc image

# https://linuxcnc.org/iso/

# unzip and flash iso

sudo apt update
sudo apt install  linuxcnc-ethercat

sudo apt install ethercat-master libethercat-dev  linuxcnc-ethercat

sudo geany /etc/ethercat.conf

MASTER0_DEVICE="xx:aa:yy:zz:bb:cc"
DEVICE_MODULES="generic"

sudo systemctl enable ethercat.service
sudo systemctl start ethercat.service
sudo systemctl status ethercat.service
sudo chmod 666 /dev/EtherCAT0


# check

ethercat slaves

sudo geany /etc/udev/rules.d/99-ethercat.rules

KERNEL=="EtherCAT[0-9]", MODE="0777"

sudo udevadm control --reload-rules

reboot

```


```shell
# direct from etherlab


sudo apt install -y autoconf automake libtool

git clone https://gitlab.com/etherlab.org/ethercat.git

cd ethercat

git switch -c stable-1.5 origin/stable-1.5

# may have to set proper ethercat compatible driver

./bootstrap

# on intel

./configure --enable-cycles --enable-8139too=no --sysconfdir=/etc

# on others

./configure --sysconfdir=/etc


make -j$(nproc) all modules

sudo make modules_install install

sudo depmod

sudo vim /etc/ethercat.conf

MASTER0_DEVICE="xx:aa:yy:zz:bb:cc"
DEVICE_MODULES="generic"

sudo systemctl enable ethercat.service

sudo systemctl start ethercat.service

sudo vim /etc/udev/rules.d/99-ethercat.rules

KERNEL=="EtherCAT[0-9]", MODE="0777"

sudo udevadm control --reload-rules

```


```shell
# after the above

# get servo motor xml from vendor site

# pdo mapping (get offset)

# sdo send (set parameters)

# logic...

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

# BUILDROOT

```shell

sudo apt-get update

sudo apt-get -y install make binutils build-essential diffutils patch gzip bzip2 perl tar cpio unzip rsync file bc findutils wget libelf-dev libncurses5-dev python-is-python3

git clone git://git.busybox.net/buildroot

cd buildroot

git switch -c lts origin/2019.08.x

find ./configs -name '*_defconfig'

# make the defconfig

# ex)

make qemu_x86_64_defconfig

make menuconfig

# target options

# build options

# toolchain options

# system configuration

# kernel

# targat packages

# filesystem images

make -j$(nproc)

# output

./output/images

# vm

# hypervisor

i440fx

bios

# os

generic

# boot options


# at start-qemu.sh

direct kernel boot

kernel path: bzimage
kernel args: rootwait root=/dev/vda console=tty1 console=ttyS0 ip=dhcp

# storage

change ide to virtio disk

# network interface

model virtio

# serial 1

# and delete all other hardwares

```


# YOCTO 


```shell

# https://docs.yoctoproject.org/brief-yoctoprojectqs/index.html


sudo apt install gawk wget git diffstat unzip texinfo gcc build-essential chrpath socat cpio python3 python3-pip python3-pexpect xz-utils debianutils iputils-ping python3-git python3-jinja2 libegl1-mesa libsdl1.2-dev python3-subunit mesa-common-dev zstd liblz4-tool file locales libacl1

sudo locale-gen en_US.UTF-8


git clone git://git.yoctoproject.org/poky



# check lts

# https://wiki.yoctoproject.org/wiki/Releases

git switch -c scarthgap origin/scarthgap

source oe-init-build-env

# tweak conf?

bitbake core-image-sato


# create vm

# disk, bzimage at

# tmp/deploy/images

# direct kernel boot

# kernel args 

root=/dev/sda ip=dhcp

# nic

e1000

```


# VPN IPSEC LIBRESWAN XL2TPD


```shell
# script ubuntu/debian

# server

vpn-socks5/server-install/swan.sh

```

```shell

# server

# open udp port 500, 4500

# add

# /etc/ipsec.d/ikev2.conf

authby=rsa-sha1

sudo service ipsec restart
```

```shell

# client

sudo apt-get update
sudo apt-get install strongswan libcharon-extra-plugins

# get p12

openssl pkcs12 -in vpnclient.p12 -cacerts -nokeys -out ca.cer
openssl pkcs12 -in vpnclient.p12 -clcerts -nokeys -out client.cer
openssl pkcs12 -in vpnclient.p12 -nocerts -nodes  -out client.key


sudo cp ca.cer /etc/ipsec.d/cacerts

sudo cp client.cer /etc/ipsec.d/certs

sudo cp client.key /etc/ipsec.d/private

sudo vim /etc/ipsec.conf

# ipsec.conf - strongSwan IPsec configuration file

# basic configuration

config setup
        # strictcrlpolicy=yes
        # uniqueids = no

# Add connections here.

conn ikev2-rw
    right=34.83.103.130
    rightid=%34.83.103.130
    rightsubnet=0.0.0.0/0
    rightauth=pubkey
    leftsourceip=%config
    leftauth=pubkey
    leftcert=client.cer
    #eap_identity=username, only if leftauth=eap (e.g. peer)
    auto=add


sudo vim /etc/ipsec.secrets

# This file holds shared secrets or RSA private keys for authentication.

# RSA private key for this host, authenticating it to any other host
# which knows the public part.
#

: RSA client.key


sudo ipsec restart

sudo ipsec status

sudo ipsec up ikev2-rw

sudo ipsec down ikev2-rw



# do manual resolvectl if not set 

sudo resolvectl dns enp1s0 8.8.8.8 8.8.4.4


```



```shell

# client nmcli

sudo apt-get update
sudo apt-get install network-manager-strongswan

# get p12

openssl pkcs12 -in vpnclient.p12 -cacerts -nokeys -out ca.cer
openssl pkcs12 -in vpnclient.p12 -clcerts -nokeys -out client.cer
openssl pkcs12 -in vpnclient.p12 -nocerts -nodes  -out client.key


nano /usr/lib/NetworkManager/conf.d/10-globally-managed-devices.conf 


[keyfile]
unmanaged-devices=none

sudo systemctl restart NetworkManager

sudo nmcli d

# if not managed

sudo nmcli dev set enp1s0 managed yes

sudo nmcli c add type vpn ifname -- vpn-type strongswan connection.id VPN connection.autoconnect no vpn.data 'address = 34.27.245.236, certificate = /home/seantywork/ca.cer, encap = no, esp = aes128gcm16, ipcomp = no, method = key, proposal = yes, usercert = /home/seantywork/client.cer, userkey = /home/seantywork/client.key, virtual = yes'


sudo nmcli c up 'Wired connection 1'

sudo nmcli c up VPN

sudo nmcli c down VPN

```

# VPN STRONGSWAN 


```shell
# server


apt install strongswan libcharon-extra-plugins strongswan-pki -y

ipsec pki --gen --size 4096 --type rsa --outform pem > ca.key.pem
ipsec pki --self --in ca.key.pem --type rsa --dn "CN=VPN Server CA" --ca --lifetime 3650 --outform pem > ca.cert.pem
ipsec pki --gen --size 4096 --type rsa --outform pem > server.key.pem
ipsec pki --pub --in server.key.pem --type rsa | ipsec pki --issue --lifetime 2750 --cacert ca.cert.pem --cakey ca.key.pem --dn "CN=vpn.example.com" --san "vpn.example.com" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem

cp -f ca.cert.pem /etc/ipsec.d/cacerts/
cp -f server.cert.pem /etc/ipsec.d/certs/
cp -f ca.key.pem /etc/ipsec.d/private/
cp -f server.key.pem /etc/ipsec.d/private/

# for client
ipsec pki --gen --type rsa --size 4096 --outform pem > client.key.pem
ipsec pki --pub --in client.key.pem --type rsa | ipsec pki --issue --lifetime 3650 --cacert ca.cert.pem --cakey ca.key.pem --dn "CN=vpnclient" --san vpnclient --outform pem > client.cert.pem
openssl pkcs12 -export -inkey client.key.pem -in client.cert.pem -name "vpnclient" -certfile ca.cert.pem -caname "VPN Server CA" -out client.p12
sudo /bin/cp -Rf client.p12 /tmp/client.p12
sudo chmod 777 /tmp/client.p12

vim  /etc/ipsec.conf

config setup
        charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"
        strictcrlpolicy=no
        uniqueids=never
        cachecrls=no
        
conn ipsec-ikev2-vpn
      auto=add
      compress=no
      type=tunnel  # defines the type of connection, tunnel.
      keyexchange=ikev2
      fragmentation=yes
      forceencaps=yes
      dpdaction=clear
      dpddelay=300s
      rekey=no
      left=%any
      leftid=@vpn.example.com    # if using IP, define it without the @ sign
      leftcert=server.cert.pem  # reads the VPN server cert in /etc/ipsec.d/certs
      leftsendcert=always
      leftsubnet=0.0.0.0/0
      right=%any
      rightid=%any
      rightauth=pubkey
      rightsourceip=192.168.43.0/24
      rightdns=8.8.8.8 #DNS to be assigned to clients
      rightsendcert=always
      esp=aes256-sha256-modp2048

vi /etc/ipsec.secret

: RSA "server.key.pem"



```

```shell

# client 

# get p12

scp server@server.com:/tmp/client.p12 .

# from client
sudo apt update
sudo apt install strongswan libcharon-extra-plugins libssl-dev -y
suod cp -f client.p12 /etc/ipsec.d/private

# /etc/ipsec.conf 
conn ipsec-ikev2-vpn-client
    auto=start
    right=192.168.10.25
    rightid=vpn.example.com
    rightsubnet=0.0.0.0/0
    rightauth=pubkey
    leftsourceip=%config
    leftid=vpnclient
    leftauth=pubkey
    mediation=no

# /etc/ipsec.secret 
: P12 client.p12 ""

```


```shell

# swanctl


sudo apt-get update

sudo apt-get -y install strongswan-swanctl charon-systemd strongswan-pki libcharon-extra-plugins libstrongswan-standard-plugins libstrongswan-extra-plugins libtss2-tcti-tabrmd-dev


sudo pki --gen --size 4096 --type rsa --outform pem > ca.key.pem
sudo pki --self --in ca.key.pem --type rsa --dn "CN=VPN Server CA" --ca --lifetime 3650 --outform pem > ca.cert.pem
sudo pki --gen --size 4096 --type rsa --outform pem > server.key.pem
sudo pki --pub --in server.key.pem --type rsa | pki --issue --lifetime 2750 --cacert ca.cert.pem --cakey ca.key.pem --dn "CN=vpn.example.com" --san "vpn.example.com" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem

sudo /bin/cp -Rf ca.cert.pem /etc/swanctl/x509ca/
sudo /bin/cp -Rf server.cert.pem /etc/swanctl/x509/
sudo /bin/cp -Rf server.key.pem /etc/swanctl/private/

# for client

sudo pki --gen --type rsa --size 4096 --outform pem > client.key.pem
sudo pki --pub --in client.key.pem --type rsa | pki --issue --lifetime 3650 --cacert ca.cert.pem --cakey ca.key.pem --dn "CN=test.client" --san test.client --outform pem > client.cert.pem


sudo /bin/cp -Rf ca.cert.pem /tmp/ca.cert.pem
sudo /bin/cp -Rf client.cert.pem /tmp/client.cert.pem
sudo /bin/cp -Rf client.key.pem /tmp/client.key.pem

sudo chmod 777 /tmp/ca.cert.pem
sudo chmod 777 /tmp/client.cert.pem
sudo chmod 777 /tmp/client.key.pem

# for client done


# /etc/swanctl/swanctl.conf

connections {

   rw {
      local_addrs  = %any
      pools = rw_pool
      version = 2
      proposals = aes256-sha256-modp2048
      unique = never
      encap = yes

      local {
         auth = pubkey
         certs = server.cert.pem
         id = vpn.example.com
      }
      remote {
         auth = pubkey
      }
      children {
         net {
            local_ts  = 10.168.0.0/24
            mode = tunnel
            esp_proposals = aes256-sha256
            dpd_action = restart
            rekey_time = 0
         }
      }
   }
}

pools{
	rw_pool {
		addrs = 10.168.0.0/24
	}
}


sudo systemctl restart strongswan



```




```shell

# swanctl whitelist, attr-sql


sudo apt-get update

sudo apt-get -y install build-essential make libgmp-dev libsystemd-dev libcurl4-openssl-dev libldap-dev libtss2-dev libgcrypt20-dev libpam0g-dev libip4tc-dev pkg-config init sqlite3 libsqlite3-dev


curl -L https://github.com/strongswan/strongswan/releases/download/6.0.0/strongswan-6.0.0.tar.gz -o strongswan-6.0.0.tar.gz

tar -xzf strongswan-6.0.0.tar.gz

pushd strongswan-6.0.0


./configure --prefix=/usr --sysconfdir=/etc --enable-charon --enable-systemd \
--disable-defaults \
--enable-static \
--enable-test-vectors \
--enable-pki --enable-ikev2 --enable-vici --enable-swanctl \
--enable-ldap \
--enable-pkcs11 \
--enable-tpm \
--enable-aesni \
--enable-aes \
--enable-rc2 \
--enable-sha2 \
--enable-sha1 \
--enable-md5 \
--enable-mgf1 \
--enable-rdrand \
--enable-random \
--enable-nonce \
--enable-x509 \
--enable-revocation \
--enable-constraints \
--enable-pubkey \
--enable-pkcs1 \
--enable-pkcs7 \
--enable-pkcs8 \
--enable-pkcs12 \
--enable-pgp \
--enable-dnskey \
--enable-sshkey \
--enable-pem \
--enable-openssl \
--enable-gcrypt \
--enable-af-alg \
--enable-fips-prf  \
--enable-gmp  \
--enable-curve25519 \
--enable-agent \
--enable-chapoly \
--enable-xcbc \
--enable-cmac \
--enable-hmac \
--enable-ctr \
--enable-ccm \
--enable-gcm \
--enable-ntru \
--enable-drbg \
--enable-curl \
--enable-attr \
--enable-kernel-netlink \
--enable-resolve \
--enable-socket-default \
--enable-connmark \
--enable-forecast \
--enable-farp \
--enable-stroke \
--enable-vici \
--enable-updown \
--enable-eap-identity \
--enable-eap-aka \
--enable-eap-md5 \
--enable-eap-gtc \
--enable-eap-mschapv2 \
--enable-eap-dynamic \
--enable-eap-radius \
--enable-eap-tls \
--enable-eap-ttls \
--enable-eap-peap \
--enable-eap-tnc \
--enable-xauth-generic \
--enable-xauth-eap \
--enable-xauth-pam \
--enable-tnc-tnccs \
--enable-dhcp \
--enable-lookip \
--enable-error-notify \
--enable-certexpire \
--enable-led \
--enable-addrblock \
--enable-unity \
--enable-counters \
--enable-whitelist \ 
--enable-sqlite \
--enable-attr-sql 

make 

make install

popd

sudo pki --gen --size 4096 --type rsa --outform pem > ca.key.pem
sudo pki --self --in ca.key.pem --type rsa --dn "CN=VPN Server CA" --ca --lifetime 3650 --outform pem > ca.cert.pem
sudo pki --gen --size 4096 --type rsa --outform pem > server.key.pem
sudo pki --pub --in server.key.pem --type rsa | pki --issue --lifetime 2750 --cacert ca.cert.pem --cakey ca.key.pem --dn "CN=vpn.example.com" --san "vpn.example.com" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem

sudo /bin/cp -Rf ca.cert.pem /etc/swanctl/x509ca/
sudo /bin/cp -Rf server.cert.pem /etc/swanctl/x509/
sudo /bin/cp -Rf server.key.pem /etc/swanctl/private/

# for client

sudo pki --gen --type rsa --size 4096 --outform pem > client.key.pem
sudo pki --pub --in client.key.pem --type rsa | pki --issue --lifetime 3650 --cacert ca.cert.pem --cakey ca.key.pem --dn "CN=test.client@test.org" --san "test.client@test.org" --outform pem > client.cert.pem


sudo /bin/cp -Rf ca.cert.pem /tmp/ca.cert.pem
sudo /bin/cp -Rf client.cert.pem /tmp/client.cert.pem
sudo /bin/cp -Rf client.key.pem /tmp/client.key.pem

sudo chmod 777 /tmp/ca.cert.pem
sudo chmod 777 /tmp/client.cert.pem
sudo chmod 777 /tmp/client.key.pem

# for client done


# /etc/swanctl/swanctl.conf

connections {

   rw {
      local_addrs  = %any
      pools = rw_pool
      version = 2
      proposals = aes256-sha256-modp2048
      unique = never
      encap = yes

      local {
         auth = pubkey
         certs = server.cert.pem
         id = vpn.example.com
      }
      remote {
         auth = pubkey
      }
      children {
         net {
            local_ts  = 10.168.0.0/24
            mode = tunnel
            esp_proposals = aes256-sha256
            dpd_action = restart
            rekey_time = 0
         }
      }
   }
}

pools{
	rw_pool {
		addrs = 10.168.0.0/24
	}
}


sudo systemctl restart strongswan



# whitelist 

sudo /usr/libexec/ipsec/whitelist enable

sudo /usr/libexec/ipsec/whitelist add test.client@test.org 

sudo /usr/libexec/ipsec/whitelist list

sudo /usr/libexec/ipsec/whitelist disable


# attr-sql 

# setup 

pushd strongswan-6.0.0

sqlite3 ${DB_PATH} < scr/pool/sqlite.sql 

sudo vim /etc/strongswan.d/charon/attr-sql.conf

database = sqlite://${DB_PATH}

load = yes 

sudo systemctl restart strongswan 

# cmd

sudo ipsec pool --status 

udo ipsec pool --add rw_pool --addresses ./address.txt

# address.txt example

10.168.100.12=test.client@test.org

udo ipsec pool --del rw_pool



```


```shell

# swanctl client

sudo apt-get update


sudo apt-get -y install strongswan-swanctl charon-systemd strongswan-pki libcharon-extra-plugins libstrongswan-standard-plugins libstrongswan-extra-plugins libtss2-tcti-tabrmd-dev 



sudo /bin/cp -Rf ca.cert.pem /etc/swanctl/x509ca
sudo /bin/cp -Rf client.cert.pem /etc/swanctl/x509
sudo /bin/cp -Rf client.key.pem /etc/swanctl/private


connections {
    home {
      remote_addrs = 192.168.101.25
      vips = 0.0.0.0
      version = 2
      proposals = aes256-sha256-modp2048

      local {
        auth = pubkey
        certs = client.cert.pem
        id = test.client
      }
      remote {
        auth = pubkey
        id = vpn.example.com
      }
      children {
        home {
          remote_ts  = 10.168.0.0/24
          start_action = start
          esp_proposals = aes256-sha256
        }
      }
    }
}

sudo systemctl restart strongswan


sudo swanctl --initiate --child $NAME

sudo swanctl --list-sas

sudo swanctl --terminate --ike-id $ID

```

# VPN OPENVPN

```shell

# ubuntu 

vpn-socks5/server-install/openvpn.sh


```


```shell

# client 

sudo apt update
# sudo apt install openvpn

sudo apt-get install openvpn


sudo openvpn --config ovclient.ovpn 
```




# VPN WIREGURAD

```shell
# ubuntu

vpn-socks5/server-install/wireguard.sh

```

```shell

# client

sudo apt update
sudo apt install wireguard

# paste generated client conf
sudo vim /etc/wireguard/wgclient.conf



# tunnel

sudo vim /etc/wireguard/wgclient.conf

PostUp = ip rule add table 200 from 192.168.0.13
PostUp = ip route add table 200 default via 192.168.0.1
PreDown = ip rule delete table 200 from 192.168.0.13
PreDown = ip route delete table 200 default via 192.168.0.1


[Peer]


# up

sudo wg-quick up wgclient

# down

sudo wg-quick down wgclient


```


# UDP BUFFER SIZE

```shell

sudo sysctl -w net.core.rmem_max=7500000

sudo sysctl -w net.core.wmem_max=7500000

```


# GUI FYNE

```shell

# after installing go, gcc

sudo apt-get update

sudo apt-get install -y libgl1-mesa-dev xorg-dev



```


# GUI AUTOMATION ROBOT 

```shell

# after installing go, gcc

# x11
sudo apt install libx11-dev xorg-dev libxtst-dev

# Clipboard
sudo apt install xsel xclip

# Bitmap
sudo apt install libpng++-dev

# GoHook
sudo apt install xcb libxcb-xkb-dev x11-xkb-utils libx11-xcb-dev libxkbcommon-x11-dev libxkbcommon-dev


```

# TURN SERVER COTURN WEBRTC


```shell

sudo apt-get update

sudo apt-get install coturn


sudo nano /etc/default/coturn

TURNSERVER_ENABLED=1

sudo systemctl start coturn


nano /etc/turnserver.conf

listening-ip=0.0.0.0

listening-port=3478

external-ip=feebdaed.xyz/192.168.0.1

min-port=3479
max-port=3579


verbose


fingerprint

user=test:test123

lt-cred-mech

realm=feebdaed.xyz


sudo systemctl restart coturn


```

```shell

# webrtc ports


# server udp mux: 8006 (custom)

# turn udp : 3478

# turn relay udp: 3479-3579

# ephemeral udp range : 31000-31100 (custom)


```



# VIM NEOVIM NVIM

```shell

# copy
# $LINENUMyy

99yy

# paste

p

# set number

:set nu

# unset number

:set nonu

# set paste

:set paste

# goto
# :$LINENUM

:33

# search

/$BLAH

# set tab spaces
set expandtab ts=4 sw=4 ai


```


# RAYLIB

```shell

sudo apt install libasound2-dev libx11-dev libxrandr-dev libxi-dev libgl1-mesa-dev libglu1-mesa-dev libxcursor-dev libxinerama-dev libwayland-dev libxkbcommon-dev

```

# KANIKO

```shell

apiVersion: v1
kind: Pod
metadata:
  name: kaniko
spec:
  containers:
  - name: kaniko
    image: gcr.io/kaniko-project/executor:latest
    args: ["--dockerfile=Dockerfile",
            "--context=git://github.com/seantywork/target.git",
	          "--context-sub-path=subdir/",
            "--destination=seantywork.com/library/test"] 
    volumeMounts:
      - name: kaniko-secret
        mountPath: /kaniko/.docker
    env:
      - name: GIT_USERNAME
        value: "$YOUR_ID"
      - name: GIT_PASSWORD
        value: "$YOUR_PASS"
  restartPolicy: Never
  volumes:
    - name: kaniko-secret
      secret:
        secretName: regcred
        items:
          - key: .dockerconfigjson
            path: config.json


```


# DPDK

```shell

# qemu kvm
# fstack

# Install dependencies for F-Stack
sudo apt install build-essential make libssl-dev python3 python-is-python3 

# get fstack release

# Install libnuma-dev
yum install numactl-devel          # on Centos
#sudo apt-get install libnuma-dev  # on Ubuntu

# Install dependencies (FreeBSD only)
#pkg install meson pkgconf py38-pyelftools

cd f-stack
# Compile DPDK

# fix for virtual machine

$FSTACK_DIR/dpdk/kernel/linux/igb_uio/igb_uio.c

-   if (pci_intx_mask_supported(udev->pdev)) {
+   if (true || pci_intx_mask_supported(udev->pdev)) {

cd dpdk/usertools
./dpdk-setup.sh # compile with x86_64-native-linuxapp-gcc

# Set hugepage (Linux only)
# single-node system
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# or NUMA (Linux only)
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

# Using Hugepage with the DPDK (Linux only)
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Close ASLR; it is necessary in multiple process (Linux only)
echo 0 > /proc/sys/kernel/randomize_va_space

# Install python for running DPDK python scripts
sudo apt install python # On ubuntu
#sudo pkg install python # On FreeBSD

# Offload NIC
# For Linux:
modprobe uio
insmod /data/f-stack/dpdk/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
insmod /data/f-stack/dpdk/x86_64-native-linuxapp-gcc/kmod/rte_kni.ko carrier=on # carrier=on is necessary, otherwise need to be up `veth0` via `echo 1 > /sys/class/net/veth0/carrier`
python dpdk-devbind.py --status
ip link set dev eth0 down
python dpdk-devbind.py --bind=igb_uio eth0 # assuming that use 10GE NIC and eth0

# Install DPDK
cd ../x86_64-native-linuxapp-gcc
make install

# On Ubuntu, use gawk instead of the default mawk.
#sudo apt-get install gawk  # or execute `sudo update-alternatives --config awk` to choose gawk.

# Install dependencies for F-Stack
sudo apt install gcc make libssl-dev                            # On ubuntu
#sudo pkg install gcc gmake openssl pkgconf libepoll-shim       # On FreeBSD



# Compile F-Stack
export FF_PATH=/$FSTACK_DIR
export FF_DPDK=/$FSRACK_DIR/dpdk/x86_64-native-linuxapp-gcc
cd ../../lib/

# disable RSS in source code

#lib/ff_dpdk_if.c 
#edit

port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;

make    # On Linux
#gmake   # On FreeBSD

# Install F-STACK
# libfstack.a will be installed to /usr/local/lib
# ff_*.h will be installed to /usr/local/include
# start.sh will be installed to /usr/local/bin/ff_start
# config.ini will be installed to /etc/f-stack.conf
make install    # On Linux
#gmake install   # On FreeBSD


# kni
ip link set dev veth0 up

ip addr add 192.168.1.2/24 dev veth0

ip route add 0.0.0.0 via 192.168.1.1 dev veth0

```


```shell

# gcloud tutorial

# https://cloud.google.com/compute/docs/networking/use-dpdk


# create vpc for data plane

## new subnet > region name (ex us-west1) , ipv4 range (ex 10.0.0.0/24)

# create vpc for control plane

## new subnet > region name (must be same as dp, ex us-west1), ipv4 range (must be different from dp, ex 10.0.1.0/24), enable ssh firewall rule


# create vm

## region must be same as dp

## going with e2-medium

## ubuntu 22 x64

## network card: virtio

## add two interfaces, control plane, data plane


# connect to vm

# get env

sudo apt-get update && sudo apt-get upgrade -yq
sudo apt-get install -yq build-essential ninja-build python3-pip linux-headers-$(uname -r) pkg-config libnuma-dev
sudo pip install pyelftools meson

# get dpdk

wget https://fast.dpdk.org/rel/dpdk-23.07.tar.xz
tar xvf dpdk-23.07.tar.xz
cd dpdk-23.07

# build dpdk

meson setup -Dexamples=all build

sudo ninja -C build install; sudo ldconfig


# check iommu-less vfio

cat /boot/config-$(uname -r) | grep NOIOMMU

CONFIG_VFIO_NOIOMMU=y

## load noiommu, vfio

sudo modprobe vfio enable_unsafe_noiommu_mode=1

sudo modprobe vfio-pci

## enable noiommu

sudo bash -c 'echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode'

# alternative, uio

## install uio

git clone https://dpdk.org/git/dpdk-kmods

pushd dpdk-kmods/linux/igb_uio
sudo make
sudo depmod && sudo insmod igb_uio.ko
popd

## or 

sudo apt-get install -y dpdk-igb-uio-dkms

sudo modprobe igb_uio


# bind dpdk

## check pci, get data plane slot

sudo lspci | grep -e "gVNIC" -e "Virtio network device"

## down

sudo ip link set ens5 down

## bind

sudo dpdk-devbind.py --bind=vfio-pci 00:05.0

## or, if uio

sudo dpdk-devbind.py --bind=igb_uio 00:05.0

## create huge page

sudo mkdir /mnt/huge

sudo mount -t hugetlbfs -o pagesize=1G none /mnt/huge

sudo bash -c 'echo 4 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages'
sudo bash -c 'echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'

## test

sudo ./build/app/dpdk-testpmd

# unbind dpdk

sudo dpdk-devbind.py -u 00:05.0

## if virtio-pci

sudo bash -c 'echo 00:05.0 > /sys/bus/pci/drivers/virtio-pci/bind'

## if gvnic

sudo bash -c 'echo 00:05.0 > /sys/bus/pci/drivers/gvnic/bind'

sudo ip link set ens5 up

```


# RUST

```shell

# install

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# .profile

export PATH="$PATH:$HOME/.cargo/env"
export PATH="$PATH:$HOME/.cargo/bin"

source .profile

```

# SCRCPY ANDROID SCREEN MIRRORING

```shell

# enable usb debugging

snap install scrcpy

scrcpy

```

# DBEAVER 


```shell



# download ce

sudo apt install ./dbeaver

# public key retrieval by url

jdbc:mysql://localhost:3306/db?allowPublicKeyRetrieval=true

```

# IFTOP
```shell

iftop

```
# PERF

```shell

perf stat -d command
```

# IPERF

```shell

# tcp client

iperf -c $ADDR -t 60 -i 1

# tcp server

iperf -s

# udp client

iperf -c $ADDR -u -b 10G -t 60 -i 1

```

# KOREAN ON LINUX

```shell

sudo apt install fcitx5 fcitx5-hangul

# go to settings > region & language 

# change keyboard input to fctix5

# go to settings > keyboard

# add input source as hangul

sudo reboot

```

```shell 

apt-get install locales-all fonts-nanum 

```

```shell

# debian

sudo apt install fcitx5 fcitx5-hangul

# enter fcitx5 configuration in menu

# set as you knoe

sudo reboot

```

# LAPTOP LID CLOSE DO NOTHNG 


```shell

sudo vim /etc/systemd/logind.conf

# uncomment
# HandleLidSwitch=ignore

sudo systemctl restart systemd-logind

```

# IO URING IOURING

```shell

sudo apt install liburing

```


# AVALANCHE DUT SETUP

```shell

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.enp134s0f2.accept_redirects=0
sysctl -w net.ipv4.conf.enp134s0f2.send_redirects=0
sysctl -w net.ipv4.conf.enp134s0f0.accept_redirects=0
sysctl -w net.ipv4.conf.enp134s0f0.send_redirects=0

ethtool -G enp134s0f0 rx 4096
ethtool -G enp134s0f0 tx 4096
ethtool -G enp134s0f2 rx 4096
ethtool -G enp134s0f2 tx 4096

net.ipv4.neigh.default.gc_stale_time=57600
net.ipv4.neigh.default.gc_thresh1 = 32768
net.ipv4.neigh.default.gc_thresh2 = 32768
net.ipv4.neigh.default.gc_thresh3 = 32768


##########################################
#                                        #
#                  DUT                   #
#  10.4.11.237/16     192.168.200.237/16 #
## if0 ############## if1 ################
   #                  #
   #                  #
   #                  #
   #                  #
   #                  #
10.1.5.0/16 + 20000   192.168.200.0 + ? (8, 16...) 
   #
tun(192.168.0.0/16 + 20000)  

# height means tunnel per sec
# if 8 cores, set it to the multiples of 8
# 8, 16, 24, 32, 64...
# and client action and server count shoud match, 8
# if server count and client action doubled, tunnel per sec doubles also
# responder ips should be server ips


```