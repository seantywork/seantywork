# podman 

- [code](https://github.com/seantywork/seantywork/tree/main/data-container-podman)

Here, I'm going to lay out how to use `podman` to create and mangage containers on Linux.



```shell

# in case of podman


vim ~/.config/containers/registries.conf

unqualified-search-registries = ["docker.io"]


# login

podman login

# logout 

podman logout

# pull 

podman pull image:tag

# tag 

podman tag orgimg/test newimg/test 

# push 

podman push newimg/test

# build 

podman build -t image-name:tag .

# export 

podman save localhost/image-name:latest -o test.tar.gz

# import 

podman load -i test.tar.gz

# util

podman image ...
podman container ...
podman network ...
podman volume ... 

# network

podman network create --driver=bridge cbr0

# network ls

podman network ls

# network rm 

podman network rm cbr0

# run with name

podman run --rm --name name0  -p 8080:80 localhost/image-name

# run with network

podman run --rm --network cbr0  -p 8080:80 localhost/image-name

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