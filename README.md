# hello-bpf


# switch to nightly
```shell
rustup default nightly
```

# require
```shell
yum install make
yum install elfutils-libelf-devel

```
# debug
cat /sys/kernel/debug/tracing/trace_pipe

sudo cat /proc/kallsyms | grep finish_task_switch

cat /proc/10295/maps

