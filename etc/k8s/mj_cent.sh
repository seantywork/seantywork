#!/bin/bash

##### ENV SECTION

ENV_CHK=""

### base env
local_ip=""

### master env

MASTER_IP=""

LB_IP=""
PORT=""

###########################

if [[ "$local_ip" == "$ENV_CHK"  ]]
then
        echo "Set local_ip to proceed"
        exit
fi

if [[ "$MASTER_IP" == "$ENV_CHK"  ]]
then
        echo "Set MASTER_IP to proceed"
        exit
fi

if [[ "$LB_IP" == "$ENV_CHK"  ]]
then
        echo "Set LB_IP to proceed"
        exit
fi

if [[ "$PORT" == "$ENV_CHK"  ]]
then
        echo "Set PORT to proceed"
        exit
fi

sudo systemctl enable --now haproxy

sudo yum install -y dnf

sudo dnf install -y yum-utils

systemctl stop firewalld

systemctl disable firewalld --now


sudo modprobe overlay
sudo modprobe br_netfilter

cat <<EOF | sudo tee /etc/modules-load.d/containerd.conf
overlay
br_netfilter
EOF

cat <<EOF | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

sudo sysctl --system

sudo yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo
OS_REL=$(cat /etc/redhat-release)
# I only had to remove Podman on CentOS Stream 8
if [[ $OS_REL == 'CentOS Stream release 8' ]]; then
  sudo dnf remove -y podman; 
fi
# If you experience a conflict with buildah, then also remove buildah with dnf.

sudo dnf install -y containerd.io

sudo mkdir -p /etc/containerd
sudo containerd config default | sudo tee /etc/containerd/config.toml
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
sudo systemctl restart containerd
sudo systemctl enable --now containerd

sudo setenforce 0
sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config

cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-\$basearch
enabled=1
gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
exclude=kubelet kubeadm kubectl
EOF
sudo yum install -y kubelet kubeadm kubectl \
--disableexcludes=kubernetes

sudo systemctl enable --now kubelet

sudo swapoff -a

VERSION="v1.24.1"
curl -L https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-${VERSION}-linux-amd64.tar.gz --output crictl-${VERSION}-linux-amd64.tar.gz
sudo tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/local/bin
rm -f crictl-$VERSION-linux-amd64.tar.gz


cat > /etc/default/kubelet << EOF
KUBELET_EXTRA_ARGS=--node-ip=$local_ip
EOF


###############################
# MASTER
###############################


NODENAME=$(hostname -s)
POD_CIDR="10.10.0.0/16"

HOME=/root

sudo kubeadm config images pull 

echo "Preflight Check Passed: Downloaded All Required Images"

sudo kubeadm init --apiserver-advertise-address=$MASTER_IP --apiserver-cert-extra-sans="$MASTER_IP,$LB_IP" --pod-network-cidr=$POD_CIDR --node-name "$NODENAME" --control-plane-endpoint "$LB_IP:$PORT" --ignore-preflight-errors Swap 
mkdir -p "$HOME"/.kube
sudo cp -i /etc/kubernetes/admin.conf "$HOME"/.kube/config
sudo chown "$(id -u)":"$(id -g)" "$HOME"/.kube/config



curl https://docs.projectcalico.org/manifests/calico.yaml -O

kubectl apply -f calico.yaml

kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
