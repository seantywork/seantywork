FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /workspace

RUN apt-get update 

RUN apt-get install -y ncat curl iproute2 ca-certificates

CMD ["tail", "-f","/dev/null"]
