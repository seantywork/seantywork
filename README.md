# seantywork

crap compilation of interesting stuff including linux ones

## overview

For previous articles published, see [Medium.com](https://medium.com/@seantywork).\
For publicly available source code, see [GitHub.com](https://github.com/seantywork).\
[This](https://github.com/seantywork/seantywork) is the main repository of this site.\
Here is the basic description of the stuff below.\

```text
    - 0x*: 
        directories beginning with `0x` are ones with special meaning,
        such as:
            - 0xadmin: 
                meta directory of this repository
            - 0xdocs:
                documents that are not related to linux
            - 0xetc:
                languages other than C, such as Go, C++, Rust...  
    - data-*:
        directories beginning with `data` are ones NOT PRIMARILY related to 
        io devices. such as:
            process, memory, data structure, algorithms...
    - dev-*:
        directories beginning with `dev` are ones PRIMARILY related to
        io devices. such as:
            network devices, disks, serials...  
    - k*:
        directories beginning with `k` are ones PRIMARILY related to
        linux kernel
    - var-*:
        directories beginning with `var` are ones NOT PRIMARILY related to
        any of above 
```
**BE AWARE**: I'm in the progress of organizing the stuff below. Some stuff might not be showing any meaningful contents.\
I'm working to get all available. \
Enjoy!

## stuff
<details>
    <ul>
        <li><a href="https://seanty.work/0xadmin/">0xadmin</a></li>
        <li><a href="https://seanty.work/0xdocs/">0xdocs</a></li>
        <li><a href="https://seanty.work/0xetc/">0xetc</a></li>
        <li><a href="https://seanty.work/data-array/">data-array</a></li>
        <li><a href="https://seanty.work/data-asm-bind-rand-tcp-port/">data-asm-bind-rand-tcp-port</a></li>
        <li><a href="https://seanty.work/data-asm-execve-bin-sh/">data-asm-execve-bin-sh</a></li>
        <li><a href="https://seanty.work/data-asm-reverse-listen/">data-asm-reverse-listen</a></li>
        <li><a href="https://seanty.work/data-byte-align/">data-byte-align</a></li>
        <li><a href="https://seanty.work/data-cgroup/">data-cgroup</a></li>
        <li><a href="https://seanty.work/data-container-kube-net/">data-container-kube-net</a></li>
        <li><a href="https://seanty.work/data-container-podman/">data-container-podman</a></li>
        <li><a href="https://seanty.work/data-cpu-affinity-thread/">data-cpu-affinity-thread</a></li>
        <li><a href="https://seanty.work/data-crypt-asym/">data-crypt-asym</a></li>
        <li><a href="https://seanty.work/data-crypt-asym-quantumsafe/">data-crypt-asym-quantumsafe</a></li>
        <li><a href="https://seanty.work/data-crypt-sym/">data-crypt-sym</a></li>
        <li><a href="https://seanty.work/data-dynamic-lib/">data-dynamic-lib</a></li>
        <li><a href="https://seanty.work/data-ebpf-seccomp/">data-ebpf-seccomp</a></li>
        <li><a href="https://seanty.work/data-fault/">data-fault</a></li>
        <li><a href="https://seanty.work/data-fault-signal/">data-fault-signal</a></li>
        <li><a href="https://seanty.work/data-fork-clone-namespace/">data-fork-clone-namespace</a></li>
        <li><a href="https://seanty.work/data-fork-daemon/">data-fork-daemon</a></li>
        <li><a href="https://seanty.work/data-fork-exec/">data-fork-exec</a></li>
        <li><a href="https://seanty.work/data-fork-prctl-seccomp/">data-fork-prctl-seccomp</a></li>
        <li><a href="https://seanty.work/data-hashmap-concurrent/">data-hashmap-concurrent</a></li>
        <li><a href="https://seanty.work/data-hex/">data-hex</a></li>
        <li><a href="https://seanty.work/data-mem-shared-shm-mmap/">data-mem-shared-shm-mmap</a></li>
        <li><a href="https://seanty.work/data-pipe-fifo/">data-pipe-fifo</a></li>
        <li><a href="https://seanty.work/data-queue-channel/">data-queue-channel</a></li>
        <li><a href="https://seanty.work/data-queue-concurrent/">data-queue-concurrent</a></li>
        <li><a href="https://seanty.work/data-random/">data-random</a></li>
        <li><a href="https://seanty.work/data-signal/">data-signal</a></li>
        <li><a href="https://seanty.work/data-spawn-popen/">data-spawn-popen</a></li>
        <li><a href="https://seanty.work/data-stream/">data-stream</a></li>
        <li><a href="https://seanty.work/data-struct/">data-struct</a></li>
        <li><a href="https://seanty.work/data-sync-cond-mutex/">data-sync-cond-mutex</a></li>
        <li><a href="https://seanty.work/data-sync-coroutine/">data-sync-coroutine</a></li>
        <li><a href="https://seanty.work/data-sync-mutex/">data-sync-mutex</a></li>
        <li><a href="https://seanty.work/data-sync-rwlock/">data-sync-rwlock</a></li>
        <li><a href="https://seanty.work/data-sync-sem/">data-sync-sem</a></li>
        <li><a href="https://seanty.work/data-sync-spin-atomic/">data-sync-spin-atomic</a></li>
        <li><a href="https://seanty.work/data-sync-thread/">data-sync-thread</a></li>
        <li><a href="https://seanty.work/data-unshare/">data-unshare</a></li>
        <li><a href="https://seanty.work/data-vector/">data-vector</a></li>
        <li><a href="https://seanty.work/data-virt-qemu-kvm/">data-virt-qemu-kvm</a></li>
        <li><a href="https://seanty.work/dev-disk/">dev-disk</a></li>
        <li><a href="https://seanty.work/dev-disk-lvm/">dev-disk-lvm</a></li>
        <li><a href="https://seanty.work/dev-disk-mmap/">dev-disk-mmap</a></li>
        <li><a href="https://seanty.work/dev-disk-overlayfs/">dev-disk-overlayfs</a></li>
        <li><a href="https://seanty.work/dev-gpio-rpi/">dev-gpio-rpi</a></li>
        <li><a href="https://seanty.work/dev-infrared/">dev-infrared</a></li>
        <li><a href="https://seanty.work/dev-net-bgp/">dev-net-bgp</a></li>
        <li><a href="https://seanty.work/dev-net-br-ovs/">dev-net-br-ovs</a></li>
        <li><a href="https://seanty.work/dev-net-can-sock/">dev-net-can-sock</a></li>
        <li><a href="https://seanty.work/dev-net-ebpf-xdp/">dev-net-ebpf-xdp</a></li>
        <li><a href="https://seanty.work/dev-net-ethtool/">dev-net-ethtool</a></li>
        <li><a href="https://seanty.work/dev-net-firewall/">dev-net-firewall</a></li>
        <li><a href="https://seanty.work/dev-net-http-request/">dev-net-http-request</a></li>
        <li><a href="https://seanty.work/dev-net-http-server/">dev-net-http-server</a></li>
        <li><a href="https://seanty.work/dev-net-ip-netfilter/">dev-net-ip-netfilter</a></li>
        <li><a href="https://seanty.work/dev-net-quic-bench/">dev-net-quic-bench</a></li>
        <li><a href="https://seanty.work/dev-net-vpn-ipsec/">dev-net-vpn-ipsec</a></li>
        <li><a href="https://seanty.work/dev-net-vpn-openvpn/">dev-net-vpn-openvpn</a></li>
        <li><a href="https://seanty.work/dev-net-vpn-wireguard/">dev-net-vpn-wireguard</a></li>
        <li><a href="https://seanty.work/dev-net-websocket/">dev-net-websocket</a></li>
        <li><a href="https://seanty.work/dev-serial-i2c/">dev-serial-i2c</a></li>
        <li><a href="https://seanty.work/dev-serial-pwm/">dev-serial-pwm</a></li>
        <li><a href="https://seanty.work/dev-serial-spi/">dev-serial-spi</a></li>
        <li><a href="https://seanty.work/dev-serial-uart/">dev-serial-uart</a></li>
        <li><a href="https://seanty.work/dev-sock-dpdk/">dev-sock-dpdk</a></li>
        <li><a href="https://seanty.work/dev-sock-dtls-udp/">dev-sock-dtls-udp</a></li>
        <li><a href="https://seanty.work/dev-sock-epoll-tcp/">dev-sock-epoll-tcp</a></li>
        <li><a href="https://seanty.work/dev-sock-epoll-tcp-async-pool/">dev-sock-epoll-tcp-async-pool</a></li>
        <li><a href="https://seanty.work/dev-sock-io-uring-http/">dev-sock-io-uring-http</a></li>
        <li><a href="https://seanty.work/dev-sock-netlink/">dev-sock-netlink</a></li>
        <li><a href="https://seanty.work/dev-sock-poll-tcp/">dev-sock-poll-tcp</a></li>
        <li><a href="https://seanty.work/dev-sock-quic/">dev-sock-quic</a></li>
        <li><a href="https://seanty.work/dev-sock-raw-mmap-packet-ip/">dev-sock-raw-mmap-packet-ip</a></li>
        <li><a href="https://seanty.work/dev-sock-raw-packet-arp/">dev-sock-raw-packet-arp</a></li>
        <li><a href="https://seanty.work/dev-sock-select-tcp/">dev-sock-select-tcp</a></li>
        <li><a href="https://seanty.work/dev-sock-tcp/">dev-sock-tcp</a></li>
        <li><a href="https://seanty.work/dev-sock-tcp-thread/">dev-sock-tcp-thread</a></li>
        <li><a href="https://seanty.work/dev-sock-tls/">dev-sock-tls</a></li>
        <li><a href="https://seanty.work/dev-sock-tls-quantum-safe/">dev-sock-tls-quantum-safe</a></li>
        <li><a href="https://seanty.work/dev-sock-tls-thread/">dev-sock-tls-thread</a></li>
        <li><a href="https://seanty.work/dev-sock-udp/">dev-sock-udp</a></li>
        <li><a href="https://seanty.work/dev-sock-unix/">dev-sock-unix</a></li>
        <li><a href="https://seanty.work/dev-sock-vpn-socks5/">dev-sock-vpn-socks5</a></li>
        <li><a href="https://seanty.work/dev-sonar/">dev-sonar</a></li>
        <li><a href="https://seanty.work/kbuild/">kbuild</a></li>
        <li><a href="https://seanty.work/kbuild-rt/">kbuild-rt</a></li>
        <li><a href="https://seanty.work/kcrypt/">kcrypt</a></li>
        <li><a href="https://seanty.work/kdev-char/">kdev-char</a></li>
        <li><a href="https://seanty.work/kdev-char-storage/">kdev-char-storage</a></li>
        <li><a href="https://seanty.work/kdev-gpio/">kdev-gpio</a></li>
        <li><a href="https://seanty.work/kdev-gpio-irqsock/">kdev-gpio-irqsock</a></li>
        <li><a href="https://seanty.work/kdev-misc/">kdev-misc</a></li>
        <li><a href="https://seanty.work/kdev-net-eth/">kdev-net-eth</a></li>
        <li><a href="https://seanty.work/kdev-net-veth/">kdev-net-veth</a></li>
        <li><a href="https://seanty.work/kdev-net-wlan/">kdev-net-wlan</a></li>
        <li><a href="https://seanty.work/kdma/">kdma</a></li>
        <li><a href="https://seanty.work/kfault/">kfault</a></li>
        <li><a href="https://seanty.work/kfs-debug/">kfs-debug</a></li>
        <li><a href="https://seanty.work/kfs-proc/">kfs-proc</a></li>
        <li><a href="https://seanty.work/kfs-sys/">kfs-sys</a></li>
        <li><a href="https://seanty.work/kioctl/">kioctl</a></li>
        <li><a href="https://seanty.work/kirq-bh-workqueue/">kirq-bh-workqueue</a></li>
        <li><a href="https://seanty.work/kirq-tbh-tasklet/">kirq-tbh-tasklet</a></li>
        <li><a href="https://seanty.work/kirq-th/">kirq-th</a></li>
        <li><a href="https://seanty.work/klog/">klog</a></li>
        <li><a href="https://seanty.work/kmem-allocpage/">kmem-allocpage</a></li>
        <li><a href="https://seanty.work/kmem-kmalloc/">kmem-kmalloc</a></li>
        <li><a href="https://seanty.work/kmem-krealloc/">kmem-krealloc</a></li>
        <li><a href="https://seanty.work/kmem-vmalloc/">kmem-vmalloc</a></li>
        <li><a href="https://seanty.work/kmodlib/">kmodlib</a></li>
        <li><a href="https://seanty.work/kmodparam/">kmodparam</a></li>
        <li><a href="https://seanty.work/kneigh/">kneigh</a></li>
        <li><a href="https://seanty.work/knetfilter/">knetfilter</a></li>
        <li><a href="https://seanty.work/knetlink/">knetlink</a></li>
        <li><a href="https://seanty.work/kproc/">kproc</a></li>
        <li><a href="https://seanty.work/kptr-share/">kptr-share</a></li>
        <li><a href="https://seanty.work/ksync-mutex/">ksync-mutex</a></li>
        <li><a href="https://seanty.work/ksync-rcu/">ksync-rcu</a></li>
        <li><a href="https://seanty.work/ksync-rcu-cmap/">ksync-rcu-cmap</a></li>
        <li><a href="https://seanty.work/ksync-spin/">ksync-spin</a></li>
        <li><a href="https://seanty.work/ksync-thread/">ksync-thread</a></li>
        <li><a href="https://seanty.work/ksysinfo/">ksysinfo</a></li>
        <li><a href="https://seanty.work/ktimer/">ktimer</a></li>
        <li><a href="https://seanty.work/kxdp/">kxdp</a></li>
        <li><a href="https://seanty.work/kxfrm/">kxfrm</a></li>
        <li><a href="https://seanty.work/var-camera-rtmp/">var-camera-rtmp</a></li>
        <li><a href="https://seanty.work/var-cat/">var-cat</a></li>
        <li><a href="https://seanty.work/var-cmake-build-pipe/">var-cmake-build-pipe</a></li>
        <li><a href="https://seanty.work/var-grep/">var-grep</a></li>
        <li><a href="https://seanty.work/var-mitm-tls/">var-mitm-tls</a></li>
        <li><a href="https://seanty.work/var-ncat/">var-ncat</a></li>
        <li><a href="https://seanty.work/var-spoof-arp/">var-spoof-arp</a></li>
        <li><a href="https://seanty.work/var-sql/">var-sql</a></li>
        <li><a href="https://seanty.work/var-stack-overflow/">var-stack-overflow</a></li>
        <li><a href="https://seanty.work/var-ten-k/">var-ten-k</a></li>
        <li><a href="https://seanty.work/var-wc/">var-wc</a></li>
    </ul>
</details>
