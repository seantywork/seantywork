FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /workspace

RUN apt-get update 

RUN apt-get install -y ncat tshark

CMD ["tail", "-f","/dev/null"]
