# insmod left.ko
```shell

[  +0.000447] init: left job scheduled
[  +0.001711] LEFT ADDR: ffffffffc0e075c0
[  +0.000003] LEFT: left message
[  +2.042100] LEFT ADDR: ffffffffc0e075c0
[  +0.000018] LEFT: left message
[  +2.047996] LEFT ADDR: ffffffffc0e075c0
[  +0.000021] LEFT: left message

```

# insmod right.ko 
```shell

[  +1.315626] RIGHT: init
[  +0.000003] (RIGHT)LEFT ADDR: ffffffffc0e075c0
[  +0.000002] (RIGHT)LEFT MESSAGE: left message
[  +0.000001] RIGHT: wrote new message
[  +0.732281] LEFT ADDR: ffffffffc0e075c0
[  +0.000005] LEFT: new message from right
[  +2.048020] LEFT ADDR: ffffffffc0e075c0
[  +0.000005] LEFT: new message from right


```

# rmmod right
```shell

[  +2.047800] LEFT ADDR: ffffffffc0e075c0
[  +0.000004] LEFT: new message from right
[  +0.734667] exit: right done
[  +1.313375] LEFT ADDR: ffffffffc0e075c0
[  +0.000008] LEFT: new message from right

```

# rmmod left
```shell
[  +1.525553] exit: left exiting, wait for job completion...
[  +0.522363] LEFT: job exit
[  +0.000028] exit: left exiting, wait done
[  +0.000005] exit: left done

```