#!/bin/bash

sudo apt update
sudo apt install -y openjdk-21-jdk

wget https://dlcdn.apache.org/maven/maven-3/3.9.12/binaries/apache-maven-3.9.12-bin.tar.gz

tar xzf apache-maven-3.9.12-bin.tar.gz

cd apache-maven-3.9.12

mvnbin="$(pwd)/bin"

echo export PATH="$mvnbin:$PATH" >> ~/.profile

wget https://nexus.opendaylight.org/content/repositories/opendaylight.release/org/opendaylight/integration/karaf/0.22.1/karaf-0.22.1.tar.gz

tar xzf karaf-0.22.1.tar.gz

cd karaf-0.22.1

echo "source ~/.profile"
echo "./bin/karaf"
