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
