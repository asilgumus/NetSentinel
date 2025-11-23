import argparse
import time
import threading
import signal
import sys
import json
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timezone
from dateutil import tz
from scapy.all import sniff, IP, TCP, UDP, Raw  # scapy
import logging
import requests  # optional webhook alerts

# -----------------------
# Configurable defaults
# -----------------------
WINDOW_SEC = 60                # sliding window length (seconds)
SYN_THRESHOLD = 50             # SYN packets from same IP within WINDOW_SEC -> alert
UNIQ_PORT_THRESHOLD = 20       # number of different destination ports from same IP within WINDOW_SEC -> alert
STEALTH_THRESHOLD = 8          # number of NULL/FIN/XMAS packets -> alert
UDP_THRESHOLD = 50             # UDP packets threshold (for noisy UDP scan detection)
CLEANUP_INTERVAL = 5           # seconds for cleanup loop
BLOCK_DURATION = 3600          # seconds to keep iptables block
LOG_FILE = "apd_scan_alerts.jsonl"
METRICS_PRINT_INTERVAL = 30    # seconds (0 to disable)
# -----------------------

# iptables command template (Linux)
IPTABLES_BLOCK_CMD = ["iptables", "-I", "INPUT", "-s", "{ip}", "-j", "DROP"]
IPTABLES_UNBLOCK_CMD = ["iptables", "-D", "INPUT", "-s", "{ip}", "-j", "DROP"]

# internal state
state = defaultdict(lambda: deque())   # ip -> deque of (ts, dport, flags, proto)
blocked = {}                           # ip -> blocked_at timestamp
lock = threading.Lock()
stop_event = threading.Event()

# Logging setup (json-lines)
logger = logging.getLogger("APD")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_FILE)
fh.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(fh)
console = logging.StreamHandler(sys.stdout)
console.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(console)

def now_ts():
    return time.time()

def iso_now():
    return datetime.now(timezone.utc).astimezone(tz.tzlocal()).isoformat()

def log_event(obj):
    # write JSON line
    line = json.dumps(obj, ensure_ascii=False)
    logger.info(line)

def is_null_flags(tcpflags):
    # NULL scan: flags == 0
    return int(tcpflags) == 0

def is_fin_flag(tcpflags):
    return bool(int(tcpflags) & 0x01)

def is_xmas_flag(tcpflags):
    # XMAS: FIN(0x01) + PSH(0x08) + URG(0x20) => 0x29 (decimal 41)
    return int(tcpflags) & 0x29 == 0x29

def handle_alert(src_ip, reason, details, args):
    obj = {
        "time": iso_now(),
        "src_ip": src_ip,
        "reason": reason,
        "details": details
    }
    log_event(obj)
    # print friendly
    print(f"[ALERT] {iso_now()} {src_ip} {reason} {details}")
    # webhook if provided
    if args.webhook:
        try:
            requests.post(args.webhook, json=obj, timeout=5)
        except Exception as e:
            print(f"[WARN] Webhook failed: {e}")

    # autoblock
    if args.autoblock and not args.dry_run:
        with lock:
            if src_ip in blocked:
                return
            try:
                cmd = [c.format(ip=src_ip) for c in [IPTABLES_BLOCK_CMD[0]] ]  # dummy to avoid lint
            except Exception:
                pass
            try:
                # run iptables insert
                cmd = ["iptables", "-I", "INPUT", "-s", src_ip, "-j", "DROP"]
                subprocess.check_call(cmd)
                blocked[src_ip] = now_ts()
                print(f"[INFO] Blocked {src_ip} via iptables for {args.block_duration}s")
                # schedule unblock
                t = threading.Timer(args.block_duration, unblock_ip, args=(src_ip,))
                t.daemon = True
                t.start()
            except Exception as e:
                print(f"[ERROR] Failed to block {src_ip} (need root & iptables): {e}")

def unblock_ip(ip):
    with lock:
        if ip not in blocked:
            return
        try:
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.check_call(cmd)
            print(f"[INFO] Unblocked {ip}")
        except Exception as e:
            print(f"[ERROR] Failed to unblock {ip}: {e}")
        blocked.pop(ip, None)

def analyze_ip(ip, args):
    """
    Analyze deque for a source ip. Called with lock held.
    """
    dq = state.get(ip)
    if not dq:
        return
    cutoff = now_ts() - args.window
    # drop old
    while dq and dq[0][0] < cutoff:
        dq.popleft()
    if not dq:
        state.pop(ip, None)
        return

    syn_count = sum(1 for (ts, dport, flags, proto) in dq if proto == 'TCP' and (int(flags) & 0x02))
    unique_ports = len({dport for (_, dport, _, _) in dq if dport})
    stealth_count = sum(1 for (_, dport, flags, proto) in dq if proto == 'TCP' and (is_null_flags(flags) or is_xmas_flag(flags) or is_fin_flag(flags)))
    udp_count = sum(1 for (_, dport, flags, proto) in dq if proto == 'UDP')

    # detection logic
    if syn_count >= args.threshold_syn:
        details = {"syn_count": syn_count, "unique_ports": unique_ports, "window": args.window}
        handle_alert(ip, "SYN_SCAN", details, args)
    elif unique_ports >= args.threshold_ports:
        details = {"unique_ports": unique_ports, "syn_count": syn_count, "window": args.window}
        handle_alert(ip, "PORT_SCAN", details, args)
    elif stealth_count >= args.threshold_stealth:
        details = {"stealth_count": stealth_count, "window": args.window}
        handle_alert(ip, "STEALTH_SCAN", details, args)
    elif udp_count >= args.threshold_udp:
        details = {"udp_count": udp_count, "window": args.window}
        handle_alert(ip, "UDP_NOISY", details, args)

def packet_callback(pkt, args, whitelist):
    try:
        if IP not in pkt:
            return
        src = pkt[IP].src
        # skip whitelist
        if src in whitelist:
            return
        ts = now_ts()
        proto = None
        dport = None
        flags = 0
        if TCP in pkt:
            proto = 'TCP'
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            dport = int(tcp.dport)
        elif UDP in pkt:
            proto = 'UDP'
            udp = pkt[UDP]
            dport = int(udp.dport)
        else:
            return

        with lock:
            state[src].append((ts, dport, flags, proto))
            # quick check: analyze only this src to be efficient
            analyze_ip(src, args)
    except Exception as e:
        print(f"[ERROR] packet_callback: {e}")

def cleanup_loop(args):
    while not stop_event.is_set():
        time.sleep(args.cleanup_interval)
        cutoff = now_ts() - args.window
        with lock:
            # clean state deques
            ips = list(state.keys())
            for ip in ips:
                dq = state[ip]
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                if not dq:
                    state.pop(ip, None)
            # cleanup blocked entries older than block_duration + grace
            expired = [ip for ip, t0 in blocked.items() if now_ts() - t0 > args.block_duration + 10]
            for ip in expired:
                blocked.pop(ip, None)

def metrics_printer(args):
    if args.metrics_interval <= 0:
        return
    while not stop_event.is_set():
        time.sleep(args.metrics_interval)
        with lock:
            total_tracked = len(state)
            top_ips = sorted(((ip, len(q)) for ip, q in state.items()), key=lambda x: x[1], reverse=True)[:10]
            print(f"[METRICS {iso_now()}] tracked_ips={total_tracked} blocked={len(blocked)} top={top_ips}")

def parse_args():
    p = argparse.ArgumentParser(description="Advanced Port Scan Detector & Auto-Block")
    p.add_argument("--iface", required=True, help="Network interface to sniff (e.g. eth0)")
    p.add_argument("--window", type=int, default=WINDOW_SEC, help="Sliding window seconds")
    p.add_argument("--threshold-syn", type=int, default=SYN_THRESHOLD, help="SYN packet threshold (window)")
    p.add_argument("--threshold-ports", type=int, default=UNIQ_PORT_THRESHOLD, help="Unique destination ports threshold (window)")
    p.add_argument("--threshold-stealth", type=int, default=STEALTH_THRESHOLD, help="Stealth packet threshold (window)")
    p.add_argument("--threshold-udp", type=int, default=UDP_THRESHOLD, help="UDP packet threshold (window)")
    p.add_argument("--cleanup-interval", type=int, default=CLEANUP_INTERVAL)
    p.add_argument("--autoblock", action="store_true", help="Enable automatic iptables blocking (dangerous: test first)")
    p.add_argument("--block-duration", type=int, default=BLOCK_DURATION, help="Seconds to keep iptables block")
    p.add_argument("--dry-run", action="store_true", help="Only alert, do not modify iptables")
    p.add_argument("--whitelist", nargs="*", default=["127.0.0.1", "10.0.0.1"], help="IPs to ignore")
    p.add_argument("--webhook", default=None, help="Optional webhook URL to POST alerts")
    p.add_argument("--metrics-interval", type=int, default=METRICS_PRINT_INTERVAL, help="Periodic metrics print interval (seconds); 0 disables")
    return p.parse_args()

def signal_handler(sig, frame):
    print("[INFO] Signal received, shutting down...")
    stop_event.set()
    # try to gracefully stop sniff by exiting
    sys.exit(0)

def main():
    args = parse_args()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # safety: if autoblock & dry-run both set, prioritize dry-run false? We keep dry-run to prevent accidental blocks
    if args.autoblock and args.dry_run:
        print("[WARN] --autoblock and --dry-run both set: will NOT modify iptables (dry-run). Remove --dry-run to enable real blocking.")

    print(f"[INFO] Starting detector on iface={args.iface} window={args.window}s, syn_threshold={args.threshold_syn}, ports_threshold={args.threshold_ports}")
    whitelist = set(args.whitelist)

    # start cleanup thread
    t_cleanup = threading.Thread(target=cleanup_loop, args=(args,), daemon=True)
    t_cleanup.start()
    # metrics thread
    t_metrics = threading.Thread(target=metrics_printer, args=(args,), daemon=True)
    t_metrics.start()

    # sniff - use a BPF filter to reduce user-space workload
    bpf = "tcp or udp"
    try:
        sniff(iface=args.iface, prn=lambda p: packet_callback(p, args, whitelist), store=False, filter=bpf)
    except PermissionError:
        print("[FATAL] Need root privileges to sniff. Run with sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] sniff failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
