# OVERLAYFS

```shell
sudo mkdir /tmp/upper /tmp/overlay /mnt/merged_directories

sudo mount -t overlay overlay -olowerdir=/path/to/dir1:/path/to/dir2,upperdir=/tmp/upper,workdir=/tmp/overlay /mnt/merged_directories

```