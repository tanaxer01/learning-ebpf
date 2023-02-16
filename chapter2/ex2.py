#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(open_table);
BPF_HASH(write_table);

int open_fn(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = open_table.lookup(&uid);
    if(p != 0) counter = *p;

    counter++;
    open_table.update(&uid, &counter);

    return 0;
}

int write_fn(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = open_table.lookup(&uid);
    if(p != 0) counter = *p;

    counter++;
    write_table.update(&uid, &counter);

    return 0;
}
"""

b = BPF(text=program)

openat = b.get_syscall_fnname("openat")
write  = b.get_syscall_fnname("write")

b.attach_kprobe(event=openat, fn_name="open_fn")
b.attach_kprobe(event=write, fn_name="write_fn")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    print("OPEN: ", end="")
    for k,v in b["open_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s, end=" | ")

    s = ""
    print("WRITE: ", end="")
    for k,v in b["write_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
