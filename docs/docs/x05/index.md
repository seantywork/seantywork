# x05 tiny implant server cpp

- switched from csv parser to sqlite3 database

as a result, the project brought in two more denpendencies (sqlite3, libsqlite3-dev),

the reason for switching is that as I gave more thoughts about what information should be handled and managed forward,

the need for more tables became apparant and I do not want multiple .csv files rolling around.

- run script added and tested 

run script handles the AP mode installation process, server build(if not existing already), and initiation of the server.

the script has been tested (05-05-2023) on a raspberrypi machine with following specifications 

uname -a:

```bash
Linux ubuntu-rpi 5.4.0-1069-raspi #79-Ubuntu SMP PREEMPT Thu Aug 18 18:15:22 UTC 2022 aarch64 aarch64 aarch64 GNU/Linux
```

lscpu:

```bash
Architecture:                    aarch64
CPU op-mode(s):                  32-bit, 64-bit
Byte Order:                      Little Endian
CPU(s):                          4
On-line CPU(s) list:             0-3
Thread(s) per core:              1
Core(s) per socket:              4
Socket(s):                       1
Vendor ID:                       ARM
Model:                           4
Model name:                      Cortex-A53
Stepping:                        r0p4
CPU max MHz:                     1400.0000
CPU min MHz:                     600.0000
BogoMIPS:                        38.40
L1d cache:                       128 KiB
L1i cache:                       128 KiB
L2 cache:                        512 KiB
```

lsblk:

```bash
NAME        MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop0         7:0    0 57.9M  1 loop /snap/core20/1614
loop1         7:1    0   61M  1 loop /snap/lxd/22761
loop2         7:2    0 40.6M  1 loop /snap/snapd/16299
mmcblk0     179:0    0 14.9G  0 disk
├─mmcblk0p1 179:1    0  256M  0 part /boot/firmware
└─mmcblk0p2 179:2    0 14.6G  0 part /
```