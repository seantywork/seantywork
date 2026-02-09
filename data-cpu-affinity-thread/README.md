# cpu-affinity-thread

- [code](https://github.com/seantywork/seantywork/tree/main/data-cpu-affinity-thread)

In this directory is the basic way to pin a thread to a particular CPU using C on Linux.

Pinned thread will run on a specific core we specified it to run on.

Let's say, if we pin a thread on core 1, it will run on it.

The simple code in the directory creates two threads, one of whici is not pinned and the other pinned.

Use `htop` or anything to observe the effect.