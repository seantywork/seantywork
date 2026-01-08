
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