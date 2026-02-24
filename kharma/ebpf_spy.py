import sys
import os

# eBPF requires Python BCC (BPF Compiler Collection)
try:
    from bcc import BPF
    EBPF_SUPPORTED = (sys.platform == "linux")
except ImportError:
    EBPF_SUPPORTED = False

# BPF Program (C)
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(stats, u32, u64);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *val, zero = 0;
    
    val = stats.lookup_or_init(&pid, &zero);
    (*val) += size;
    return 0;
}
"""

class EBPSpy:
    """
    Kharma Sentinel eBPF Controller.
    Interacts with the Linux kernel to gather per-process network stats
    with near-zero overhead.
    """
    def __init__(self):
        self.bpf = None
        self.enabled = False
        if EBPF_SUPPORTED:
            try:
                # BCC requires root
                if os.geteuid() == 0:
                    self.bpf = BPF(text=BPF_PROGRAM)
                    self.enabled = True
                    print("[SENTINEL] eBPF Kernel Probe active.")
                else:
                    print("[SENTINEL] eBPF requires ROOT permissions. Falling back to Scapy.")
            except Exception as e:
                print(f"[SENTINEL] eBPF Initialize failed: {e}")

    def get_stats(self):
        """Returns {pid: total_bytes_sent} from kernel map."""
        if not self.enabled:
            return {}
        
        report = {}
        stats_map = self.bpf.get_table("stats")
        for k, v in stats_map.items():
            report[k.value] = v.value
        
        # We don't clear the map as bcc handles the persistent hash, 
        # but we could clear it if we wanted delta stats.
        return report

if __name__ == "__main__":
    import time
    spy = EBPSpy()
    while True:
        try:
            print(f"Stats: {spy.get_stats()}")
            time.sleep(2)
        except KeyboardInterrupt:
            break
