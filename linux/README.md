# linux

```text
    - 0xetc:
        something else,
        such as programming languages other than C, such as Go, C++, Rust...  
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

<details>
    <ul>
        <li><a href="0xetc/">0xetc</a></li>
        <li><a href="data-array/">data-array</a></li>
        <li><a href="data-byte-align/">data-byte-align</a></li>
        <li><a href="data-cgroup/">data-cgroup</a></li>
        <li><a href="data-container-kube-net/">data-container-kube-net</a></li>
        <li><a href="data-container-podman/">data-container-podman</a></li>
        <li><a href="data-cpu-affinity-thread/">data-cpu-affinity-thread</a></li>
        <li><a href="data-crypt-asym/">.data-crypt-asym</a></li>
        <li><a href="data-crypt-asym-quantumsafe/">.data-crypt-asym-quantumsafe</a></li>
        <li><a href="data-crypt-sym/">.data-crypt-sym</a></li>
        <li><a href="data-dynamic-lib/">.data-dynamic-lib</a></li>
        <li><a href="data-ebpf-seccomp/">.data-ebpf-seccomp</a></li>
        <li><a href="data-fault/">.data-fault</a></li>
        <li><a href="data-fault-signal/">.data-fault-signal</a></li>
        <li><a href="data-fork-clone-namespace/">.data-fork-clone-namespace</a></li>
        <li><a href="data-fork-daemon/">.data-fork-daemon</a></li>
        <li><a href="data-fork-exec/">.data-fork-exec</a></li>
        <li><a href="data-fork-prctl-seccomp/">.data-fork-prctl-seccomp</a></li>
        <li><a href="data-hashmap-concurrent/">.data-hashmap-concurrent</a></li>
        <li><a href="data-hex/">.data-hex</a></li>
        <li><a href="data-mem-shared-shm-mmap/">.data-mem-shared-shm-mmap</a></li>
        <li><a href="data-pipe-fifo/">.data-pipe-fifo</a></li>
        <li><a href="data-queue-concurrent/">.data-queue-concurrent</a></li>
        <li><a href="data-random/">.data-random</a></li>
        <li><a href="data-signal/">.data-signal</a></li>
        <li><a href="data-spawn-popen/">.data-spawn-popen</a></li>
        <li><a href="data-stream/">.data-stream</a></li>
        <li><a href="data-struct/">data-struct</a></li>
        <li><a href="data-sync-cond-mutex/">.data-sync-cond-mutex</a></li>
        <li><a href="data-sync-coroutine/">.data-sync-coroutine</a></li>
        <li><a href="data-sync-mutex/">.data-sync-mutex</a></li>
        <li><a href="data-sync-rwlock/">.data-sync-rwlock</a></li>
        <li><a href="data-sync-sem/">.data-sync-sem</a></li>
        <li><a href="data-sync-spin-atomic/">.data-sync-spin-atomic</a></li>
        <li><a href="data-sync-thread/">.data-sync-thread</a></li>
        <li><a href="data-unshare/">.data-unshare</a></li>
        <li><a href="data-vector/">.data-vector</a></li>
        <li><a href="data-virt-qemu-kvm/">.data-virt-qemu-kvm</a></li>
        <li><a href="dev-disk/">.dev-disk</a></li>
        <li><a href="dev-disk-lvm/">.dev-disk-lvm</a></li>
        <li><a href="dev-disk-mmap/">.dev-disk-mmap</a></li>
        <li><a href="dev-disk-overlayfs/">.dev-disk-overlayfs</a></li>
        <li><a href="dev-gpio-rpi/">.dev-gpio-rpi</a></li>
        <li><a href="dev-infrared/">.dev-infrared</a></li>
        <li><a href="dev-net-bgp/">.dev-net-bgp</a></li>
        <li><a href="dev-net-br-ovs/">.dev-net-br-ovs</a></li>
        <li><a href="dev-net-can-sock/">.dev-net-can-sock</a></li>
        <li><a href="dev-net-ebpf-xdp/">.dev-net-ebpf-xdp</a></li>
        <li><a href="dev-net-ethtool/">.dev-net-ethtool</a></li>
        <li><a href="dev-net-firewall/">.dev-net-firewall</a></li>
        <li><a href="dev-net-http-request/">.dev-net-http-request</a></li>
        <li><a href="dev-net-http-server/">.dev-net-http-server</a></li>
        <li><a href="dev-net-ip-netfilter/">.dev-net-ip-netfilter</a></li>
        <li><a href="dev-net-quic-bench/">.dev-net-quic-bench</a></li>
        <li><a href="dev-net-vpn-ipsec/">.dev-net-vpn-ipsec</a></li>
        <li><a href="dev-net-vpn-openvpn/">.dev-net-vpn-openvpn</a></li>
        <li><a href="dev-net-vpn-wireguard/">.dev-net-vpn-wireguard</a></li>
        <li><a href="dev-net-websocket/">.dev-net-websocket</a></li>
        <li><a href="dev-serial-i2c/">.dev-serial-i2c</a></li>
        <li><a href="dev-serial-pwm/">.dev-serial-pwm</a></li>
        <li><a href="dev-serial-spi/">.dev-serial-spi</a></li>
        <li><a href="dev-serial-uart/">.dev-serial-uart</a></li>
        <li><a href="dev-sock-dpdk/">.dev-sock-dpdk</a></li>
        <li><a href="dev-sock-dtls-udp/">.dev-sock-dtls-udp</a></li>
        <li><a href="dev-sock-epoll-tcp/">.dev-sock-epoll-tcp</a></li>
        <li><a href="dev-sock-epoll-tcp-async-pool/">.dev-sock-epoll-tcp-async-pool</a></li>
        <li><a href="dev-sock-io-uring-http/">.dev-sock-io-uring-http</a></li>
        <li><a href="dev-sock-netlink/">.dev-sock-netlink</a></li>
        <li><a href="dev-sock-poll-tcp/">.dev-sock-poll-tcp</a></li>
        <li><a href="dev-sock-quic/">.dev-sock-quic</a></li>
        <li><a href="dev-sock-raw-mmap-packet-ip/">.dev-sock-raw-mmap-packet-ip</a></li>
        <li><a href="dev-sock-raw-packet-arp/">.dev-sock-raw-packet-arp</a></li>
        <li><a href="dev-sock-select-tcp/">.dev-sock-select-tcp</a></li>
        <li><a href="dev-sock-tcp/">.dev-sock-tcp</a></li>
        <li><a href="dev-sock-tcp-thread/">.dev-sock-tcp-thread</a></li>
        <li><a href="dev-sock-tls/">.dev-sock-tls</a></li>
        <li><a href="dev-sock-tls-quantum-safe/">.dev-sock-tls-quantum-safe</a></li>
        <li><a href="dev-sock-tls-thread/">.dev-sock-tls-thread</a></li>
        <li><a href="dev-sock-udp/">.dev-sock-udp</a></li>
        <li><a href="dev-sock-unix/">.dev-sock-unix</a></li>
        <li><a href="dev-sock-vpn-socks5/">.dev-sock-vpn-socks5</a></li>
        <li><a href="dev-sonar/">.dev-sonar</a></li>
        <li><a href="kbuild/">.kbuild</a></li>
        <li><a href="kbuild-rt/">.kbuild-rt</a></li>
        <li><a href="kcrypt/">.kcrypt</a></li>
        <li><a href="kdev-char/">.kdev-char</a></li>
        <li><a href="kdev-char-storage/">.kdev-char-storage</a></li>
        <li><a href="kdev-gpio/">.kdev-gpio</a></li>
        <li><a href="kdev-gpio-irqsock/">.kdev-gpio-irqsock</a></li>
        <li><a href="kdev-misc/">.kdev-misc</a></li>
        <li><a href="kdev-net-eth/">.kdev-net-eth</a></li>
        <li><a href="kdev-net-veth/">.kdev-net-veth</a></li>
        <li><a href="kdev-net-wlan/">.kdev-net-wlan</a></li>
        <li><a href="kdma/">.kdma</a></li>
        <li><a href="kfault/">.kfault</a></li>
        <li><a href="kfs-debug/">.kfs-debug</a></li>
        <li><a href="kfs-proc/">.kfs-proc</a></li>
        <li><a href="kfs-sys/">.kfs-sys</a></li>
        <li><a href="kioctl/">.kioctl</a></li>
        <li><a href="kirq-bh-workqueue/">.kirq-bh-workqueue</a></li>
        <li><a href="kirq-tbh-tasklet/">.kirq-tbh-tasklet</a></li>
        <li><a href="kirq-th/">.kirq-th</a></li>
        <li><a href="klog/">.klog</a></li>
        <li><a href="kmem-allocpage/">.kmem-allocpage</a></li>
        <li><a href="kmem-kmalloc/">.kmem-kmalloc</a></li>
        <li><a href="kmem-krealloc/">.kmem-krealloc</a></li>
        <li><a href="kmem-vmalloc/">.kmem-vmalloc</a></li>
        <li><a href="kmodlib/">.kmodlib</a></li>
        <li><a href="kmodparam/">.kmodparam</a></li>
        <li><a href="kneigh/">.kneigh</a></li>
        <li><a href="knetfilter/">.knetfilter</a></li>
        <li><a href="knetlink/">.knetlink</a></li>
        <li><a href="kproc/">.kproc</a></li>
        <li><a href="kptr-share/">.kptr-share</a></li>
        <li><a href="ksync-mutex/">.ksync-mutex</a></li>
        <li><a href="ksync-rcu/">.ksync-rcu</a></li>
        <li><a href="ksync-rcu-cmap/">.ksync-rcu-cmap</a></li>
        <li><a href="ksync-spin/">.ksync-spin</a></li>
        <li><a href="ksync-thread/">.ksync-thread</a></li>
        <li><a href="ksysinfo/">.ksysinfo</a></li>
        <li><a href="ktimer/">.ktimer</a></li>
        <li><a href="kxdp/">.kxdp</a></li>
        <li><a href="kxfrm/">.kxfrm</a></li>
        <li><a href="var-camera-rtmp/">.var-camera-rtmp</a></li>
        <li><a href="var-cat/">.var-cat</a></li>
        <li><a href="var-cmake-build-pipe/">.var-cmake-build-pipe</a></li>
        <li><a href="var-grep/">.var-grep</a></li>
        <li><a href="var-mitm-tls/">.var-mitm-tls</a></li>
        <li><a href="var-ncat/">.var-ncat</a></li>
        <li><a href="var-spoof-arp/">.var-spoof-arp</a></li>
        <li><a href="var-sql/">.var-sql</a></li>
        <li><a href="var-stack-overflow/">.var-stack-overflow</a></li>
        <li><a href="var-templeos/">.var-templeos</a></li>
        <li><a href="var-ten-k/">.var-tem</a></li>
        <li><a href="var-wc/">.var-wc</a></li>
    </ul>
</details>