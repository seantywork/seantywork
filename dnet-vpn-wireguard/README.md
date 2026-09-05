# net-vpn-wireguard


```shell

# wireguard

sudo apt install wireguard

SERVER_ADDR="10.13.255.254/16"
CLIENT_ADDR="10.13.0.1/32"
RESOURCE_RANGE="10.14.0.0/24"
ENDPOINT="192.168.101.25:51820"

wg genkey > priv.pem

wg pubkey < priv.pem

sudo ip link add wg0 type wireguard

sudo ip addr add ${ADDR} dev wg0

sudo wg set wg0 private-key ./priv.pem

sudo ip link set wg0 up

# - peer pub
# - peer endpoint
sudo wg

# on server
sudo wg set wg0 peer ${PEER_PUB} allowed-ips ${PEER_ADDR} endpoint ${ENDPOINT}

# on client
sudo wg set wg0 peer ${PEER_PUB} allowed-ips ${PEER_ADDR},${RESOURCE_RANGE} endpoint ${ENDPOINT}
# on client, as traffic selector
sudo ip route add ${RESOURCE_RANGE} dev wg0


# test resource comm

set -x

sudo ip netns add v1

sudo ip link add dev wgeth1 type veth peer name wgeth2 netns v1


sudo ip netns exec v1 ip link set up wgeth2

sudo ip netns exec v1 ip addr add 10.14.0.250/24 dev wgeth2

sudo ip netns exec v1 ip route add default via 10.14.0.25 dev wgeth2

sudo ip netns exec v1 ip link set up lo

sudo ip addr add 10.14.0.25/24 dev wgeth1

sudo ip link set up wgeth1

```

