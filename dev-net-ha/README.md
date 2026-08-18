# net-ha

# keepalived

```shell
sudo apt install keepalived

```


```shell
# machine 1
vrrp_instance VI_1 {
    state MASTER
    interface br0
    virtual_router_id 51
    priority 150
    advert_int 1
    virtual_ipaddress {
        192.168.122.240/24
    }
}


```


```shell
# machine 2

vrrp_instance VI_1 {
    state BACKUP
    interface br0
    virtual_router_id 51
    priority 100
    advert_int 1
    virtual_ipaddress {
        192.168.122.240/24
    }
}

```