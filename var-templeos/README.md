# templeos

```shell
# install
qemu-img create -f qcow2 temple 2G

export QEMU_AUDIO_DRV=pa

qemu-system-x86_64 -audiodev pa,id=audio0 -machine pcspk-audiodev=audio0 -m 512M -enable-kvm -drive file=temple -cdrom TempleOS.ISO -boot order=d


```


```shell
# start
qemu-system-x86_64 -audiodev pa,id=audio0 -machine pcspk-audiodev=audio0 -m 512M -enable-kvm -drive file=temple


```