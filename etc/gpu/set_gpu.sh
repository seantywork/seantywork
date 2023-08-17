#!/bin/bash


# Adjust versions, or, you might even have to directly download driver installtion script 

sudo apt-get install linux-headers-$(uname -r)



distribution=$(. /etc/os-release;echo $ID$VERSION_ID | sed -e 's/\.//g')



wget https://developer.download.nvidia.com/compute/cuda/repos/$distribution/x86_64/cuda-keyring_1.0-1_all.deb



sudo dpkg -i cuda-keyring_1.0-1_all.deb



sudo apt-get update



sudo apt-get -y install cuda-drivers



export PATH=/usr/local/cuda-11.8/bin${PATH:+:${PATH}}



export LD_LIBRARY_PATH=/usr/local/cuda-11.8/lib64\

                         ${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}



sudo systemctl enable nvidia-persistenced



/usr/bin/nvidia-persistenced --verbose



sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit



echo "Now configure container runtime"
echo "Go to the link below to get detailed guidance"
echo "https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html"
