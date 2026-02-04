# podman 

- [code](https://github.com/seantywork/seantywork/tree/main/data-container-podman)

Here, I'm going to lay out how to use `podman` to create and mangage containers on Linux.

Why `podman` instead of `docker`? No real reason. I just happend to be more used to it than `docker`.\
But don't worry too much if you're particularly inclined to use `docker` because, what we're going to do today \
are absolutely interchangeable between those two. \
Except for a very few steps below, we can replace `podman` with `docker` and have zero problem whatsoever. 

First, let's install `podman`.

```shell
$ sudo apt update && sudo apt install -y podman

```

Simple, right? To install `docker`, we can follow the steps on [the official webpage](https://docs.docker.com/engine/install/ubuntu/)

To use `podman` with `Docker Hub`, we need following step after the successful installation.

```shell

# if we're using podman as rootless 

mkdir -p ~/.config/containers

vim ~/.config/containers/registries.conf

# copy and paste this part
unqualified-search-registries = ["docker.io"]
```
If you're going to use `podman` as root, modify the same part available at `/etc/containers/registries.conf`

After this, we can get authorization for the site using the command below.

```shell

# login

podman login ${REGISTRY_ADDRESS}

```
In the case of `Docker Hub`, we don't have to specify it because it's the default registry.

We can log out from the site using the below command if we will.

```shell

# logout 

podman logout
```

Now is the time to actually run container using images available on `Docker Hub`!\
We can pull image from the registry using `pull` command.

```shell
# pull 

podman pull image:tag
```

So, let's say if we want to pull the famous `nginx` image with tag `1.29.4` from it, we can do something like below.

```shell
$ podman pull nginx:1.29.4
Resolving "nginx" using unqualified-search registries (/home/thy/.config/containers/registries.conf)
Trying to pull docker.io/library/nginx:1.29.4...
Getting image source signatures
Copying blob bc4d011570c3 done   | 
Copying blob 0c8d55a45c0d done   | 
Copying blob 2711d25abbb0 done   | 
Copying blob 173e7a5d3717 done   | 
Copying blob 359cde133485 done   | 
Copying blob acc398fdf80e done   | 
Copying blob 1eb69ddd819c done   | 
Copying config 248d2326f3 done   | 
Writing manifest to image destination
248d2326f351e7f8dc3dae8e07c24c6b69230a96ecf71ba9d6e282989b972be5
# check the image we've just pulled
$ podman images
REPOSITORY               TAG         IMAGE ID      CREATED       SIZE
docker.io/library/nginx  1.29.4      248d2326f351  24 hours ago  164 MB
```
What do we do with the image? Run it!

```shell
$ podman run nginx:1.29.4 
/docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration
/docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/
/docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf
10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf
/docker-entrypoint.sh: Sourcing /docker-entrypoint.d/15-local-resolvers.envsh
/docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh
/docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh
/docker-entrypoint.sh: Configuration complete; ready for start up
2026/02/04 02:25:10 [notice] 1#1: using the "epoll" event method
2026/02/04 02:25:10 [notice] 1#1: nginx/1.29.4
2026/02/04 02:25:10 [notice] 1#1: built by gcc 14.2.0 (Debian 14.2.0-19) 
2026/02/04 02:25:10 [notice] 1#1: OS: Linux 6.8.0-90-generic
2026/02/04 02:25:10 [notice] 1#1: getrlimit(RLIMIT_NOFILE): 1048576:1048576
2026/02/04 02:25:10 [notice] 1#1: start worker processes
2026/02/04 02:25:10 [notice] 1#1: start worker process 24
2026/02/04 02:25:10 [notice] 1#1: start worker process 25
2026/02/04 02:25:10 [notice] 1#1: start worker process 26
# keyboard interrupt to turn off
```
Okay, what we want to do now, is to build our own custom image and fiddle with it.\
Using the `Dockerfile` available in the directory, we can do that.

Examining the file, we can see that there is nothing much about it.\
Pulling `ubuntu:24.04` image, and then install `ncat`, `curl`, and `ca-certificates`. That's all.

Now, let's build that dummy image with `podman`.

```shell
# build 

$ podman build -t mydummyimg:1.0.0 .
STEP 1/6: FROM ubuntu:24.04
Resolving "ubuntu" using unqualified-search registries (/home/thy/.config/containers/registries.conf)
Trying to pull docker.io/library/ubuntu:24.04...
Getting image source signatures
Copying blob a3629ac5b9f4 done   | 
Copying config 493218ed0f done   | 
Writing manifest to image destination
STEP 2/6: ARG DEBIAN_FRONTEND=noninteractive
--> 7812a9276e9c
STEP 3/6: WORKDIR /workspace
--> 9d51bde8340f
STEP 4/6: RUN apt-get update 
Get:1 http://security.ubuntu.com/ubuntu noble-security InRelease [126 kB]
Get:2 http://archive.ubuntu.com/ubuntu noble InRelease [256 kB]
...
COMMIT mydummyimg:1.0.0
--> 8deddd18ff9d
Successfully tagged localhost/mydummyimg:1.0.0
8deddd18ff9dfb1e1d95af29bef8be6e1043fe69165c3984345c6a6c68b5f55d
# check out the new image
$ podman images
REPOSITORY                TAG         IMAGE ID      CREATED         SIZE
localhost/mydummyimg      1.0.0       8deddd18ff9d  53 seconds ago  160 MB
docker.io/library/nginx   1.29.4      248d2326f351  25 hours ago    164 MB
docker.io/library/ubuntu  24.04       493218ed0f40  3 weeks ago     80.6 MB
```

We can change image name using `tag` command.

```shell
# tag 
# 
$ podman tag localhost/mydummyimg:1.0.0 docker.io/seantywork/mydummyimg:latest

```

If we're going to make this available through registry, we can push the image\
using the `push` command.

```shell

# push 

$ podman push docker.io/seantywork/mydummyimg:latest
Getting image source signatures
Copying blob 9b5a89dc33bf done   | 
Copying blob d07c7984c70d done   | 
Copying blob a3629ac5b9f4 skipped: already exists  
```

But, what if we want to share the image without ever having to go through `Docker Hub` or \
whatever registry that's painful to set up and maintain?

We can use `save` and `load` commands.

```shell
# export 

$ podman save docker.io/seantywork/mydummyimg:latest -o mydummyimg.latest.tar.gz
Copying blob 123a078714d5 done   | 
Copying blob 9b5a89dc33bf done   | 
Copying blob d07c7984c70d done   | 
Copying config 8deddd18ff done   | 
Writing manifest to image destination
```

Then let's wipe out the image we've built.

```shell
# check image id 
$ podman images
REPOSITORY                       TAG         IMAGE ID      CREATED         SIZE
docker.io/seantywork/mydummyimg  latest      8deddd18ff9d  10 minutes ago  160 MB
localhost/mydummyimg             1.0.0       8deddd18ff9d  10 minutes ago  160 MB
docker.io/library/nginx          1.29.4      248d2326f351  26 hours ago    164 MB
docker.io/library/ubuntu         24.04       493218ed0f40  3 weeks ago     80.6 MB
$ podman rmi -f 8deddd18ff9
```

Now, we're going to import the image we've just deleted.

```shell
# import 
$ podman load -i mydummyimg.latest.tar.gz
# check if it's imported
$ podman images
REPOSITORY                       TAG         IMAGE ID      CREATED         SIZE
docker.io/seantywork/mydummyimg  latest      8deddd18ff9d  13 minutes ago  160 MB
docker.io/library/nginx          1.29.4      248d2326f351  26 hours ago    164 MB
docker.io/library/ubuntu         24.04       493218ed0f40  3 weeks ago     80.6 MB
```

Okay, I think we've seen enough about how to create and share images so far. Now is the time \
to mess with how to run it.

To keep things simple, we're going to focus on how to run a `container`, with `network` and `volume` along with \
`command`.

First, let's create a `network` that our container is going to use.

```shell
# network
# it doesn't have to be `cbr0` obviously.
$ podman network create --driver=bridge cbr0
cbr0
```

Check what networks we have.

```shell
# network ls
$ podman network ls
NETWORK ID    NAME        DRIVER
b619d159a124  cbr0        bridge
2f259bab93aa  podman      bridge
```
We can delete network using the command below.

```shell
# network rm 

$ podman network rm cbr0
cbr0
```

We can run the container we've created using command below.

```shell
# run with name
$ podman run --rm --name mydummy docker.io/seantywork/mydummyimg
```
Sadly, since we've specified the `CMD` in Dockerfile as "tail -f /dev/null", there is no process \
interruptiple using Ctrl+C.

So we have to open another terminal and use the command below to terminate the container.

```shell
$ podman stop mydummy
WARN[0010] StopSignal SIGTERM failed to stop container mydummy in 10 seconds, resorting to SIGKILL 
mydummy

```

Now, let's run the container with the network we've created.

```shell
# run with network
$ podman run --rm --name mydummy --network cbr0 docker.io/seantywork/mydummyimg
```

All nice

```shell
# run with port

podman run --rm -p 8080:80 localhost/image-name

# run with volume

podman run --rm -v ./local:/workspace localhost/image-name

# run detached

podman run --rm -d localhost/image-name

# run with command

podman run --rm -t -v ./local:/usr/workspace localhost/image-name /bin/bash -c 'cd test && ./hello.sh'

# run with interactive 

podman run --rm -it -v ./local:/usr/workspace localhost/image-name /bin/bash -c 'cd test && ./hello.sh'

# run with environment 

podman run --rm -e MYENV=hello localhost/image-name


# exec

podman exec -it container /bin/bash

# stop 

podman stop container

```