import threading
import time
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from dateutil import tz
from scapy.all import sniff, UDP, DNS, IP
import logging
import requests
import re

DEFAULT_WINDOW = 60          # sliding window in seconds
DEFAULT_RATE_THRESHOLD = 10  # aynı domain için saniyede kaç istek uyarı üretir
DEFAULT_BLACKLIST = ["bad.com", "malware.test", "phish.example"]
DEFAULT_CLEANUP = 5

def iso_now():
    return datetime.now(timezone.utc).astimezone(tz.tzlocal()).isoformat()

class DNSMonitor:
    def __init__(self,
                 iface,
                 on_alert=None,
                 dry_run=True,
                 blacklist=None,
                 window=DEFAULT_WINDOW,
                 rate_threshold=DEFAULT_RATE_THRESHOLD,
                 cleanup_interval=DEFAULT_CLEANUP,
                 webhook=None,
                 logger=None):
        self.iface = iface
        self.on_alert = on_alert
        self.dry_run = dry_run
        self.blacklist = set(blacklist or DEFAULT_BLACKLIST)
        self.window = window
        self.rate_threshold = rate_threshold
        self.cleanup_interval = cleanup_interval
        self.webhook = webhook

        # internal state
        self._domain_history = defaultdict(lambda: deque())  # domain -> deque of timestamps
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sniffer_thread = None
        self._cleanup_thread = None
        self._logger = logger or logging.getLogger("DNSMonitor")
        self._logger.setLevel(logging.INFO)

    # -------------------
    # Public API
    # -------------------
    def start(self):
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            return
        self._stop.clear()
        self._sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._sniffer_thread.start()
        self._cleanup_thread.start()
        self._logger.info(f"[DNSMonitor] started on iface {self.iface}")

    def stop(self):
        self._stop.set()
        self._logger.info("[DNSMonitor] stopping...")

    # -------------------
    # Internal helpers
    # -------------------
    def _sniff_loop(self):
        try:
            sniff(iface=self.iface, filter="udp port 53", prn=self._packet_callback, store=False)
        except Exception as e:
            self._logger.error(f"[DNSMonitor] sniff failed: {e}")

    def _cleanup_loop(self):
        while not self._stop.is_set():
            time.sleep(self.cleanup_interval)
            cutoff = time.time() - self.window
            with self._lock:
                to_delete = []
                for domain, dq in self._domain_history.items():
                    while dq and dq[0] < cutoff:
                        dq.popleft()
                    if not dq:
                        to_delete.append(domain)
                for domain in to_delete:
                    self._domain_history.pop(domain, None)

    def _packet_callback(self, pkt):
        if not pkt.haslayer(DNS) or not pkt.haslayer(UDP) or not pkt.haslayer(IP):
            return
        dns_layer = pkt[DNS]
        ip_layer = pkt[IP]
        if dns_layer.qr != 0:  # sadece sorgular
            return
        domain = dns_layer.qd.qname.decode().rstrip(".").lower()
        ts = time.time()

        with self._lock:
            self._domain_history[domain].append(ts)
            dq = self._domain_history[domain]
            count = len(dq)

        # rate alert
        if count >= self.rate_threshold:
            self._emit_alert("HIGH_RATE_QUERY", domain, count, ip_layer.src)

        # blacklist alert
        if any(bad in domain for bad in self.blacklist):
            self._emit_alert("BLACKLIST_QUERY", domain, count, ip_layer.src)

        # simple suspicious check: random-looking domain
        if self._looks_random(domain):
            self._emit_alert("SUSPICIOUS_DOMAIN", domain, count, ip_layer.src)

    def _looks_random(self, domain):
        # basit heuristic: uzun, rastgele karakterler, 10+ chars, % letters < 0.7
        name = domain.split(".")[0]
        if len(name) < 10:
            return False
        letters = sum(c.isalpha() for c in name)
        if letters / len(name) < 0.7:
            return True
        return False

    def _emit_alert(self, reason, domain, count, src_ip):
        alert = {
            "time": iso_now(),
            "reason": reason,
            "domain": domain,
            "query_count": count,
            "src_ip": src_ip
        }
        msg = json.dumps(alert, ensure_ascii=False)
        self._logger.warning(msg)
        if callable(self.on_alert):
            try:
                self.on_alert(alert)
            except Exception as e:
                self._logger.exception(f"[DNSMonitor] on_alert callback raised: {e}")
        if self.webhook:
            try:
                requests.post(self.webhook, json=alert, timeout=5)
            except Exception as e:
                self._logger.warning(f"[DNSMonitor] webhook failed: {e}")
