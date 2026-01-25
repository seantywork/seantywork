# container-kube-net

- [code](https://github.com/seantywork/seantywork/tree/main/data-container-kube-net)

In here, I outlined how to install Kubernetes with Cilium CNI on Google Cloud (though also workable on \
local VMs) and explored how communication between pods on different nodes works.

Let's suppose we created two VMs that can fully communicate with each other. We're going to make one of them \
control node and the other worker node.

The full script to turn a VM into a control node is available as `node-ctl.sh`.

In the script at the start, we'll see the basic setup information defined as below.

```shell
HOME="/root" 
IP="10.168.0.2"
VERSION="1.33"
CILIUM_VERSION="1.17.4"

```

We should take care of the version, because it's already approaching EOL \
if we're going to use `1.33`. The IP address there refers to the VM's internal IP \
assigned by the cloud provider (in this case Google cloud)

If those are correctly configure, and Kubernetes fellas didn't mess up \
the releases once again, the `node-ctl.sh` script should work and we'd \
be able to see something like below.


```shell

root@node-0:~# kubectl get nodes
NAME     STATUS   ROLES           AGE   VERSION
node-0   Ready    control-plane   73s   v1.33.1

```

On the control node, we can create token for other nodes to join the cluster.

```shell

root@node-0:~# kubeadm token create --print-join-command 
kubeadm join 10.168.0.2:6443 --token r61w3k.oom2m7zqt6m8p0fc --discovery-token-ca-cert-hash sha256:9dcf53ebff2089c12cf3af75e4540e58674ccd44282ba0285420852e4ebc5114 
```

On the other node, we can run `node-wrk.sh` to turn it into a worker node. \
As with the control node, the variables at the start of the script should be \
configured correctly. If done, we can use token we've created on the control \
node to join the worker node.

```shell

root@node-1:~# kubeadm join 10.168.0.2:6443 --token r61w3k.oom2m7zqt6m8p0fc --discovery-token-ca-cert-hash sha256:9dcf53ebff2089c12cf3af75e4540e58674ccd44282ba0285420852e4ebc5114 
[preflight] Running pre-flight checks
[preflight] Reading configuration from the "kubeadm-config" ConfigMap in namespace "kube-system"...
[preflight] Use 'kubeadm init phase upload-config --config your-config-file' to re-upload it.
[kubelet-start] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
[kubelet-start] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
[kubelet-start] Starting the kubelet
[kubelet-check] Waiting for a healthy kubelet at http://127.0.0.1:10248/healthz. This can take up to 4m0s
[kubelet-check] The kubelet is healthy after 1.002236822s
[kubelet-start] Waiting for the kubelet to perform the TLS Bootstrap

This node has joined the cluster:
* Certificate signing request was sent to apiserver and a response was received.
* The Kubelet was informed of the new secure connection details.

Run 'kubectl get nodes' on the control-plane to see this node join the cluster.
```

Now, if we run the `kubectl` again, we'll see that the cluster is up and running.

```shell

root@node-0:~# kubectl get nodes
NAME                                             STATUS   ROLES           AGE     VERSION
node-0                                           Ready    control-plane   8m21s   v1.33.1
node-1.us-east4-b.c.vpn-server-422904.internal   Ready    <none>          47s     v1.33.1

```

Using the same procedure, we're going to create one more worker node and join it \
with the cluster as well.

```shell
root@node-2:~# kubeadm join 10.168.0.2:6443 --token r61w3k.oom2m7zqt6m8p0fc --discovery-token-ca-cert-hash sha256:9dcf53ebff2089c12cf3af75e4540e58674ccd44282ba0285420852e4ebc5114
[preflight] Running pre-flight checks
[preflight] Reading configuration from the "kubeadm-config" ConfigMap in namespace "kube-system"...
[preflight] Use 'kubeadm init phase upload-config --config your-config-file' to re-upload it.
[kubelet-start] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
[kubelet-start] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
[kubelet-start] Starting the kubelet
[kubelet-check] Waiting for a healthy kubelet at http://127.0.0.1:10248/healthz. This can take up to 4m0s
[kubelet-check] The kubelet is healthy after 1.003909562s
[kubelet-start] Waiting for the kubelet to perform the TLS Bootstrap

This node has joined the cluster:
* Certificate signing request was sent to apiserver and a response was received.
* The Kubelet was informed of the new secure connection details.

Run 'kubectl get nodes' on the control-plane to see this node join the cluster.

```

Now we have a total of three nodes making up the cluster!

```shell

root@node-0:~# kubectl get nodes
NAME                                             STATUS   ROLES           AGE    VERSION
node-0                                           Ready    control-plane   12m    v1.33.1
node-1.us-east4-b.c.vpn-server-422904.internal   Ready    <none>          5m3s   v1.33.1
node-2.us-east4-b.c.vpn-server-422904.internal   Ready    <none>          51s    v1.33.1
```

For our purpose of this tutorial where we want to track how a packet flows through \
between two nodes, we're going to need a method to pin down a container on `node-1` \
and the other on `node-2`.

To do so, we can use node labelling provided by Kubernetes.

```shell

root@node-0:~# kubectl label node node-1.us-east4-b.c.vpn-server-422904.internal nodelabel=node-wrk-1 
node/node-1.us-east4-b.c.vpn-server-422904.internal labeled
root@node-0:~# kubectl label node node-2.us-east4-b.c.vpn-server-422904.internal nodelabel=node-wrk-2
node/node-2.us-east4-b.c.vpn-server-422904.internal labeled
```

Also, to add another layer of separation(though not needed for the purpose \
of this tutorial), we're going create namespce for each as well. 

```shell

root@node-0:~# kubectl create namespace wrk-1
namespace/wrk-1 created
root@node-0:~# kubectl create namespace wrk-2
namespace/wrk-2 created
root@node-0:~# vim 1.yaml
```

Look at the YAML file below (also available in the directory) with which we're \
going to create. This is the YAML for creating a pod on `node1`. The other YAML \
file looks similar except for names used for the pod.

What it does is essentially opening up a port 9999 on TCP, UDP so that other pods \
can talk to the pod using the channel.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: node-wrk-1-ubuntu24
  labels:
    app: node-wrk-1-ubuntu24
spec:
  type: ClusterIP
  ports:
  - name: tcp-9999
    port: 9999
    targetPort: 9999
    protocol: TCP
  - name: udp-9999
    port: 9999
    targetPort: 9999
    protocol: UDP
  selector:
    app: node-wrk-1-ubuntu24
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: node-wrk-1-ubuntu24
spec:
  selector:
    matchLabels:
      app: node-wrk-1-ubuntu24
  replicas: 1
  template:
    metadata:
      labels:
        app: node-wrk-1-ubuntu24
    spec:
      containers:
        - name: node-wrk-1-ubuntu24
          image: docker.io/seantywork/ubuntu24
          imagePullPolicy: Always
          ports:
          - containerPort: 9999
            protocol: TCP
          - containerPort: 9999
            protocol: UDP
      nodeSelector:
        nodelabel: node-wrk-1

```

Now, let's look at what exactly is going on inside the pod.

```Dockerfile
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /workspace

RUN apt-get update 

RUN apt-get install -y ncat tshark

CMD ["tail", "-f","/dev/null"]
```

Well, nothing at all. Because what we want to do is to capture the network packets \
as they fly around, not actually up and running a service.


Let's create the first pod on the worker node 1.

```shell
root@node-0:~# kubectl -n wrk-1 apply -f ./1.yaml 
service/node-wrk-1-ubuntu24 created
deployment.apps/node-wrk-1-ubuntu24 created
```

If successful, we'd be able to see the below status. 


```shell

root@node-0:~# kubectl -n wrk-1 get pods 
NAME                                   READY   STATUS    RESTARTS   AGE
node-wrk-1-ubuntu24-684f7d8fd6-2zncq   1/1     Running   0          112s
```

Do the same thing for the second pod on the worker node 2.

```shell

root@node-0:~# kubectl -n wrk-2 apply -f ./2.yaml 
service/node-wrk-2-ubuntu24 created
deployment.apps/node-wrk-2-ubuntu24 created

# a few seconds later...

root@node-0:~# kubectl -n wrk-2 get pods 
NAME                                   READY   STATUS    RESTARTS   AGE
node-wrk-2-ubuntu24-85748464f7-mwmrt   1/1     Running   0          3m5s

```

To inspect packets on the host machines (not inside the pod), let's install \
`tshark` on each node.

```shell

# on node 1
root@node-1:~# apt update && apt install -y tshark
# on node 2
root@node-2:~# apt update && apt install -y tshark
```

When I set up a brand-new cluster, I prefer to restart `coredns` just in case.

```shell

root@node-0:~# kubectl -n kube-system rollout restart deployment coredns 
```

Now, we're going to keep two terminals opened for persistent connection to each pod. 

```shell
# terminal 1
root@node-0:~# kubectl -n wrk-1 get pods
NAME                                   READY   STATUS    RESTARTS   AGE
node-wrk-1-ubuntu24-684f7d8fd6-2zncq   1/1     Running   0          13m
root@node-0:~# kubectl -n wrk-1 exec -it node-wrk-1-ubuntu24-684f7d8fd6-2zncq -- /bin/bash
root@node-wrk-1-ubuntu24-684f7d8fd6-2zncq:/workspace# 

# terminal 2
root@node-0:~# kubectl -n wrk-2 get pods
NAME                                   READY   STATUS    RESTARTS   AGE
node-wrk-2-ubuntu24-85748464f7-mwmrt   1/1     Running   0          11m
root@node-0:~# kubectl -n wrk-2 exec -it node-wrk-2-ubuntu24-85748464f7-mwmrt -- /bin/bash
root@node-wrk-2-ubuntu24-85748464f7-mwmrt:/workspace# 

```

In this case, I'm going to run a simple TCP server inside the second pod and a client from \
the first pod.

```shell
# run the server inside the pod 2, with port 9999
root@node-wrk-2-ubuntu24-85748464f7-mwmrt:/workspace# nc -l 0.0.0.0 9999

# connect to the server, with ${SERVICE_NAME}.${NAMESPACE_NAME}, then send whatever payload
# from the pod 1
root@node-wrk-1-ubuntu24-684f7d8fd6-2zncq:/workspace# nc node-wrk-2-ubuntu24.wrk-2 9999
asdfasdfasdfasd

# ...got the data on the pod 2!
root@node-wrk-2-ubuntu24-85748464f7-mwmrt:/workspace# nc -l 0.0.0.0 9999
asdfasdfasdfasd
```

To find out where exactly to put our mighty `tshark` to work, we need to figure out \
which network interface our pods are using to communicate with each other. To do so, \
we're going to start a long running process inside the pod, and then look for it for \
each of network namespaces (because pods are essentially glorified Linux network namespace)

```shell
root@node-wrk-1-ubuntu24-684f7d8fd6-2zncq:/workspace# sleep 3000

```

Let's see what namespaces we have on `worker 1`.

```shell

root@node-1:~# ip netns list
36322294-9a3a-47fd-8be4-6530f0123581 (id: 2)
5b58d4f1-eb3e-4cb7-b823-bbb08ee37b18 (id: 1)
02aa7ed5-2d8b-44ff-9865-d1b2ef17665c
dbe865d4-e332-40cc-8d95-459445ff6574
a300e0fa-b79e-48b5-aabf-bd8bbcebc428

```

Seeing `id: 1` on the entry `5b58d4f1-eb3e-4cb7-b823-bbb08ee37b18`, out of a blind guessing that \
it might be the namespace we're looking for because there is no other pod we've created on the `worker 1`,\
I ran `grep` command on `ps` output. It reveals the guess was correct. This is the namespace we're looking for,\
indeed.

```shell

root@node-1:~# ip netns exec 5b58d4f1-eb3e-4cb7-b823-bbb08ee37b18 ps aux | grep sleep
root       85586  0.0  0.0   2696  1380 pts/1    S+   00:41   0:00 sleep 3000
```

To find out the interface IP address inside the pod, run `ip` command.\
It shows that if when we communicate with other services outside the pod `, the source \
IP address will be `10.0.1.15`.

```shell
root@node-1:~# ip netns exec 5b58d4f1-eb3e-4cb7-b823-bbb08ee37b18 ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
8: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1460 qdisc noqueue state UP group default qlen 1000
    link/ether 4e:e0:85:d5:68:f9 brd ff:ff:ff:ff:ff:ff link-netns 02aa7ed5-2d8b-44ff-9865-d1b2ef17665c
    inet 10.0.1.15/32 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::4ce0:85ff:fed5:68f9/64 scope link 
       valid_lft forever preferred_lft forever
```

To check out which interface on host is connected to our `pod 1`, we can use interface info. We can see in the info \
that the namespace `5b58d4f1-eb3e-4cb7-b823-bbb08ee37b18` is connected to the host interface `lxc7dc050ebabd6`. Look at \
`link-netns` field in the info.

```shell
root@node-1:~# ip -d link show 
...
9: lxc7dc050ebabd6@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1460 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether a6:8a:15:36:dc:cb brd ff:ff:ff:ff:ff:ff link-netns 5b58d4f1-eb3e-4cb7-b823-bbb08ee37b18 promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    veth addrgenmode eui64 numtxqueues 2 numrxqueues 2 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
11: lxc1e0b7c2c5527@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1460 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 0e:9c:2c:8c:64:77 brd ff:ff:ff:ff:ff:ff link-netns 36322294-9a3a-47fd-8be4-6530f0123581 promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    veth addrgenmode eui64 numtxqueues 2 numrxqueues 2 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536

root@node-1:~# ip netns list
36322294-9a3a-47fd-8be4-6530f0123581 (id: 2)
5b58d4f1-eb3e-4cb7-b823-bbb08ee37b18 (id: 1)
....

```

If we run the same `nc` command we've run just a moment ago again, but with `tshark` attached to the interface `lxc7dc050ebabd6`  on `worker 1` , \
we can see DNS query followed by the actual TCP communication (and, indeed, our `pod 1`'s source IP `10.0.1.15`). 

```shell

root@node-1:~# tshark -i lxc7dc050ebabd6
Running as user "root" and group "root". This could be dangerous.
Capturing on 'lxc7dc050ebabd6'
    1 0.000000000    10.0.1.15 → 10.96.0.10   DNS 109 Standard query 0x262f A node-wrk-2-ubuntu24.wrk-2.wrk-1.svc.cluster.local
    2 0.000122975    10.0.1.15 → 10.96.0.10   DNS 109 Standard query 0xf132 AAAA node-wrk-2-ubuntu24.wrk-2.wrk-1.svc.cluster.local
    3 0.001248872   10.96.0.10 → 10.0.1.15    DNS 202 Standard query response 0xf132 No such name AAAA node-wrk-2-ubuntu24.wrk-2.wrk-1.svc.cluster.local SOA ns.dns.cluster.local
    4 0.001283013   10.96.0.10 → 10.0.1.15    DNS 202 Standard query response 0x262f No such name A node-wrk-2-ubuntu24.wrk-2.wrk-1.svc.cluster.local SOA ns.dns.cluster.local
    5 0.001410506    10.0.1.15 → 10.96.0.10   DNS 103 Standard query 0x76e7 A node-wrk-2-ubuntu24.wrk-2.svc.cluster.local
    6 0.001456907    10.0.1.15 → 10.96.0.10   DNS 103 Standard query 0x67e4 AAAA node-wrk-2-ubuntu24.wrk-2.svc.cluster.local
    7 0.001863086   10.96.0.10 → 10.0.1.15    DNS 196 Standard query response 0x67e4 AAAA node-wrk-2-ubuntu24.wrk-2.svc.cluster.local SOA ns.dns.cluster.local
    8 0.001984626   10.96.0.10 → 10.0.1.15    DNS 162 Standard query response 0x76e7 A node-wrk-2-ubuntu24.wrk-2.svc.cluster.local A 10.105.134.33
    9 0.091833823    10.0.1.15 → 10.105.134.33 TCP 74 38430 → 9999 [SYN] Seq=0 Win=64390 Len=0 MSS=1370 SACK_PERM TSval=167971729 TSecr=0 WS=128
   10 0.092468056 10.105.134.33 → 10.0.1.15    TCP 74 9999 → 38430 [SYN, ACK] Seq=0 Ack=1 Win=65184 Len=0 MSS=1370 SACK_PERM TSval=2085648661 TSecr=167971729 WS=128
   11 0.092505544    10.0.1.15 → 10.105.134.33 TCP 66 38430 → 9999 [ACK] Seq=1 Ack=1 Win=64512 Len=0 TSval=167971730 TSecr=2085648661

```

As we can see from the packet capture, the coredns returns `10.105.134.33` as the destination IP address. \
In fact, that is not exactly the "true" IP address of the `pod 2` where `nc` server is running. The part of \
Kubernetes that handles this NATing stuff is called `kube-proxy` and it could use `iptables` or `ebpf` or both combined.

If we look at the `iptables` rules on `worker 1` host, we can see the IP address `10.105.134.33` is certainly related to \
NATing if destined to `pod 2`.

```shell

root@node-1:~# iptables -t nat -L -v | grep "10.105.134.33"
    0     0 KUBE-SVC-IWPXKGE4TAJJE4GD  tcp  --  any    any     anywhere             10.105.134.33        /* wrk-2/node-wrk-2-ubuntu24:tcp-9999 cluster IP */ tcp dpt:9999
    0     0 KUBE-SVC-HX23KANCFUYJINGR  udp  --  any    any     anywhere             10.105.134.33        /* wrk-2/node-wrk-2-ubuntu24:udp-9999 cluster IP */ udp dpt:9999
    0     0 KUBE-MARK-MASQ  udp  --  any    any    !10.10.0.0/16         10.105.134.33        /* wrk-2/node-wrk-2-ubuntu24:udp-9999 cluster IP */ udp dpt:9999
    0     0 KUBE-MARK-MASQ  tcp  --  any    any    !10.10.0.0/16         10.105.134.33        /* wrk-2/node-wrk-2-ubuntu24:tcp-9999 cluster IP */ tcp dpt:9999

Chain KUBE-SVC-IWPXKGE4TAJJE4GD (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 KUBE-MARK-MASQ  tcp  --  any    any    !10.10.0.0/16         10.105.134.33        /* wrk-2/node-wrk-2-ubuntu24:tcp-9999 cluster IP */ tcp dpt:9999
    0     0 KUBE-SEP-FXHI2MOU7V5XIHJD  all  --  any    any     anywhere             anywhere             /* wrk-2/node-wrk-2-ubuntu24:tcp-9999 -> 10.0.2.215:9999 */

```

However, we have to be aware that Cilium, which we've installed along with Kubernetes to handle networking between pods, \
uses eBPF to implement the features provided by `iptables` so that the `iptables` rules output above don't show any matching \
packet stats.

To check out what eBPF programs are at work, we can use `bpftool`.

```shell
root@node-1:~/bpftool/src# bpftool link
2: tcx  prog 572  
        ifindex cilium_vxlan(5)  attach_type tcx_ingress  
3: tcx  prog 571  
        ifindex cilium_vxlan(5)  attach_type tcx_egress  
4: tcx  prog 657  
        ifindex cilium_host(4)  attach_type tcx_ingress  
5: tcx  prog 652  
        ifindex cilium_host(4)  attach_type tcx_egress  
6: tcx  prog 664  
        ifindex cilium_net(3)  attach_type tcx_ingress  
7: tcx  prog 674  
        ifindex ens4(2)  attach_type tcx_ingress  
8: tcx  prog 600  
        ifindex lxc_health(7)  attach_type tcx_ingress  
9: tcx  prog 681  
        ifindex lxc7dc050ebabd6(9)  attach_type tcx_ingress  
10: tcx  prog 694  
        ifindex lxc1e0b7c2c5527(11)  attach_type tcx_ingress 
```

Here's the source code of Cilium's eBPF program.

```shell

# https://github.com/cilium/cilium/blob/main/bpf/bpf_lxc.c
```

Also, Cilium makes possible node-to-node communication using `vxlan`. If we attach `tshark` to \
the vxlan interface, we'd be able to see the packet's final destination IP right before it gets \
tunneled inside vxlan.

```shell

root@node-1:~# tshark -i cilium_vxlan 
Running as user "root" and group "root". This could be dangerous.
Capturing on 'cilium_vxlan'
...
    3 0.153379717    10.0.1.15 → 10.0.2.17    DNS 109 Standard query 0x69a9 A node-wrk-2-ubuntu24.wrk-2.wrk-1.svc.cluster.local
    4 0.153453149    10.0.1.15 → 10.0.2.17    DNS 109 Standard query 0x71b4 AAAA node-wrk-2-ubuntu24.wrk-2.wrk-1.svc.cluster.local
    5 0.154519494    10.0.2.17 → 10.0.1.15    DNS 202 Standard query response 0x69a9 No such name A node-wrk-2-ubuntu24.wrk-2.wrk-1.svc.cluster.local SOA ns.dns.cluster.local
    6 0.156446844    10.0.2.17 → 10.0.1.15    DNS 202 Standard query response 0x71b4 No such name AAAA node-wrk-2-ubuntu24.wrk-2.wrk-1.svc.cluster.local SOA ns.dns.cluster.local
    7 0.156651889    10.0.1.15 → 10.0.2.17    DNS 103 Standard query 0x0fd2 A node-wrk-2-ubuntu24.wrk-2.svc.cluster.local
    8 0.156713018    10.0.1.15 → 10.0.2.17    DNS 103 Standard query 0xf8cf AAAA node-wrk-2-ubuntu24.wrk-2.svc.cluster.local
    9 0.157366940    10.0.2.17 → 10.0.1.15    DNS 196 Standard query response 0xf8cf AAAA node-wrk-2-ubuntu24.wrk-2.svc.cluster.local SOA ns.dns.cluster.local
   10 0.157367119    10.0.2.17 → 10.0.1.15    DNS 162 Standard query response 0x0fd2 A node-wrk-2-ubuntu24.wrk-2.svc.cluster.local A 10.105.134.33
   11 0.247844051    10.0.1.15 → 10.0.2.215   TCP 74 41208 → 9999 [SYN] Seq=0 Win=64390 Len=0 MSS=1370 SACK_PERM TSval=168433304 TSecr=0 WS=128
   12 0.248302570   10.0.2.215 → 10.0.1.15    TCP 74 9999 → 41208 [SYN, ACK] Seq=0 Ack=1 Win=65184 Len=0 MSS=1370 SACK_PERM TSval=2086110236 TSecr=168433304 WS=128
   13 0.248397099    10.0.1.15 → 10.0.2.215   TCP 66 41208 → 9999 [ACK] Seq=1 Ack=1 Win=64512 Len=0 TSval=168433305 TSecr=2086110236
...

```

`10.0.2.215`, it is.

```shell
root@node-1:~# iptables -t nat -L -v | grep 10.0.2.215
    0     0 KUBE-MARK-MASQ  all  --  any    any     10.0.2.215           anywhere             /* wrk-2/node-wrk-2-ubuntu24:tcp-9999 */
    0     0 DNAT       tcp  --  any    any     anywhere             anywhere             /* wrk-2/node-wrk-2-ubuntu24:tcp-9999 */ tcp to:10.0.2.215:9999
    0     0 KUBE-MARK-MASQ  all  --  any    any     10.0.2.215           anywhere             /* wrk-2/node-wrk-2-ubuntu24:udp-9999 */
    0     0 DNAT       udp  --  any    any     anywhere             anywhere             /* wrk-2/node-wrk-2-ubuntu24:udp-9999 */ udp to:10.0.2.215:9999
    0     0 KUBE-SEP-VWQM2HSDJBARAX5I  all  --  any    any     anywhere             anywhere             /* wrk-2/node-wrk-2-ubuntu24:udp-9999 -> 10.0.2.215:9999 */
    0     0 KUBE-SEP-FXHI2MOU7V5XIHJD  all  --  any    any     anywhere             anywhere             /* wrk-2/node-wrk-2-ubuntu24:tcp-9999 -> 10.0.2.215:9999 */

```

When we attach `tshark` on the actual interface that is connected to the switch (or whatever it is as we're using Google Cloud),
we can see that tunneled `vxlan` packets flowing between nodes.

```shell

root@node-1:~# tshark -i ens4 -f udp
Running as user "root" and group "root". This could be dangerous.
Capturing on 'ens4'
    1 0.000000000   10.168.0.4 → 10.168.0.5   UDP 159 45304 → 8472 Len=117
    2 0.000026094   10.168.0.4 → 10.168.0.5   UDP 159 45304 → 8472 Len=117
    3 0.000787520   10.168.0.5 → 10.168.0.4   UDP 252 45292 → 8472 Len=210
    4 0.000879542   10.168.0.5 → 10.168.0.4   UDP 252 45292 → 8472 Len=210
    5 0.001084107   10.168.0.4 → 10.168.0.5   UDP 153 59946 → 8472 Len=111
    6 0.001121632   10.168.0.4 → 10.168.0.5   UDP 153 59946 → 8472 Len=111
    7 0.001991176   10.168.0.5 → 10.168.0.4   UDP 246 56913 → 8472 Len=204
    8 0.003240963   10.168.0.5 → 10.168.0.4   UDP 212 56913 → 8472 Len=170
    9 0.091070101   10.168.0.4 → 10.168.0.5   UDP 124 32918 → 8472 Len=82
   10 0.091373667   10.168.0.5 → 10.168.0.4   UDP 124 43769 → 8472 Len=82
   11 0.091482484   10.168.0.4 → 10.168.0.5   UDP 116 32918 → 8472 Len=74

```

Now, we're going to move on to `worker 2`. Attach `tshark` to the interface connected to switch \
to observe the `vxlan` packets.

```shell

root@node-2:~# tshark -i ens4 -f udp
Running as user "root" and group "root". This could be dangerous.
Capturing on 'ens4'
    1 0.000000000   10.168.0.4 → 10.168.0.5   UDP 159 54392 → 8472 Len=117
    2 0.000000394   10.168.0.4 → 10.168.0.5   UDP 159 54392 → 8472 Len=117
    3 0.000924839   10.168.0.5 → 10.168.0.4   UDP 252 33949 → 8472 Len=210
    4 0.001091915   10.168.0.5 → 10.168.0.4   UDP 252 33949 → 8472 Len=210
    5 0.090827819   10.168.0.4 → 10.168.0.5   UDP 124 46625 → 8472 Len=82
    6 0.091005902   10.168.0.5 → 10.168.0.4   UDP 124 39053 → 8472 Len=82
    7 0.091299352   10.168.0.4 → 10.168.0.5   UDP 116 46625 → 8472 Len=74
```

Doing the steps on `worker 1` in reverse, we're going to look at `worker 2`'s vxlan interface. 

```shell

root@node-2:~# tshark -i cilium_vxlan -f "tcp port 9999"
Running as user "root" and group "root". This could be dangerous.
Capturing on 'cilium_vxlan'
    1 0.000000000    10.0.1.15 → 10.0.2.215   TCP 74 40686 → 9999 [SYN] Seq=0 Win=64390 Len=0 MSS=1370 SACK_PERM TSval=166156308 TSecr=0 WS=128
    2 0.000242183   10.0.2.215 → 10.0.1.15    TCP 74 9999 → 40686 [SYN, ACK] Seq=0 Ack=1 Win=65184 Len=0 MSS=1370 SACK_PERM TSval=2083833240 TSecr=166156308 WS=128
    3 0.000623879    10.0.1.15 → 10.0.2.215   TCP 66 40686 → 9999 [ACK] Seq=1 Ack=1 Win=64512 Len=0 TSval=166156309 TSecr=2083833240

```
We can see that the decapsulated vxlan packet shows our `pod 1`'s source IP and the destination IP for `pod 2`, `10.0.2.215`. 


Applying the same logic when we've found which namespace gets translated to the `pod 1` on `worker 1`, we can find that \
the `pod 2` is `ceb7eaea-1923-4233-9253-9b7d25a9fb93` on `worker 2`.

```shell
# to see all namespaces on worker 2
root@node-2:~# ip netns list
47f92595-eb21-46c7-b0ac-5efbf1cd4d59 (id: 2)
ceb7eaea-1923-4233-9253-9b7d25a9fb93 (id: 1)
fe1dc96d-ef17-4afd-a1f7-4b65bdd64bd0
c686294b-4802-4767-9057-69c83626a5ee
477ebbff-90d2-43f3-9e8f-15dbac6501f2

# ...there it is!
root@node-2:~# ip netns exec ceb7eaea-1923-4233-9253-9b7d25a9fb93 ip a
...
8: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1460 qdisc noqueue state UP group default qlen 1000
    link/ether 92:42:dd:7b:6f:be brd ff:ff:ff:ff:ff:ff link-netns fe1dc96d-ef17-4afd-a1f7-4b65bdd64bd0
    inet 10.0.2.215/32 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::9042:ddff:fe7b:6fbe/64 scope link 
       valid_lft forever preferred_lft forever
```

We can make sure the `nc` server is running in that namespace.

```shell

root@node-2:~# ip netns exec ceb7eaea-1923-4233-9253-9b7d25a9fb93 ps aux | grep nc
...
root       39372  0.0  0.1  14912  5548 pts/0    S+   May21   0:00 nc -l 0.0.0.0 9999

```

As we did on `worker 1`, we can check out which interface is connected to the namespace `ceb7eaea-1923-4233-9253-9b7d25a9fb93`.

```shell

root@node-2:~# ip -d link show
...
9: lxc3afb1f126f2c@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1460 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 52:17:b0:95:31:94 brd ff:ff:ff:ff:ff:ff link-netns ceb7eaea-1923-4233-9253-9b7d25a9fb93 promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    veth addrgenmode eui64 numtxqueues 2 numrxqueues 2 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
11: lxc3fe8b5095c99@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1460 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 72:15:1d:3a:ad:d0 brd ff:ff:ff:ff:ff:ff link-netns 47f92595-eb21-46c7-b0ac-5efbf1cd4d59 promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 
    veth addrgenmode eui64 numtxqueues 2 numrxqueues 2 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 
...
```

If we attach `tshark` on `lxc3afb1f126f2c`, it's clear the packet set sail from a namespace on `worker 1` ends up in another namespace on `worker 2`.

```shell
root@node-2:~# tshark -i lxc3afb1f126f2c
Running as user "root" and group "root". This could be dangerous.
Capturing on 'lxc3afb1f126f2c'
    1 0.000000000    10.0.1.15 → 10.0.2.215   TCP 74 50210 → 9999 [SYN] Seq=0 Win=64390 Len=0 MSS=1370 SACK_PERM TSval=173851431 TSecr=0 WS=128
    2 0.000035143   10.0.2.215 → 10.0.1.15    TCP 74 9999 → 50210 [SYN, ACK] Seq=0 Ack=1 Win=65184 Len=0 MSS=1370 SACK_PERM TSval=2091528363 TSecr=173851431 WS=128
    3 0.000359301    10.0.1.15 → 10.0.2.215   TCP 66 50210 → 9999 [ACK] Seq=1 Ack=1 Win=64512 Len=0 TSval=173851431 TSecr=2091528363

```