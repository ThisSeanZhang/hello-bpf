# hello-bpf


# switch to nightly
```shell
rustup default nightly
```

# require
```shell
# Centos
yum install make
yum install elfutils-libelf-devel

# Ubuntu
sudo apt-get install libelf-dev
sudo apt install clang
```
# debug
cat /sys/kernel/debug/tracing/trace_pipe

sudo cat /proc/kallsyms | grep finish_task_switch

cat /proc/10295/maps

