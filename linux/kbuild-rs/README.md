# kbuild-rs

```shell
# dependency
sudo apt install -y git fakeroot build-essential tar ncurses-dev \
    tar xz-utils libssl-dev bc stress libelf-dev \
    linux-headers-$(uname -r) bison flex libncurses5-dev util-linux net-tools "linux-tools-$(uname -r)" exuberant-ctags cscope \
    sysfsutils gnome-system-monitor curl perf-tools-unstable \
    gnuplot rt-tests indent tree psmisc smem libnuma-dev numactl \
    hwloc bpfcc-tools sparse flawfinder cppcheck bsdmainutils \
    trace-cmd virt-what dwarves libdw-dev \
    llvm clang lld
# download kernel source

curl -L https://mirrors.edge.kernel.org/pub/linux/kernel/v7.x/linux-7.0.tar.gz -o linux-7.0.tar.gz

# install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# add core
rustup component add rust-src
# install bindgen
cargo install --locked bindgen-cli
# add fmt
rustup component add rustfmt
# add lint
rustup component add clippy

# in kernel source
# test rust is available
make LLVM=1 rustavailable


# localmod
    LLKD_KSRC="$HOME/linux-5.5.1"
    lsmod > /tmp/lsmod.now
    cd "$LLKD_KSRC"
    make LSMOD=/tmp/lsmod.now localmodconfig
    make menuconfig

# ubuntu specific
scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS

# in kernel source
# build rust supported kernel
make LLVM=1

# now, 
# rust kernel module can be built against the source directory

make -C $THE_RUST_SUPPORTED_KERNEL_SOURCE LLVM=1 M=$PWD build
```