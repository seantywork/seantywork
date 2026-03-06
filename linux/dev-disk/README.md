
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