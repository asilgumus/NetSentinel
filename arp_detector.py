#!/usr/bin/env python3
"""
ARPDetector module for integration.

Usage pattern (in your app):
  from arp_detector_module import ARPDetector

  def on_alert(alert):
      print("ALERT CALLBACK:", alert)

  detector = ARPDetector(iface="eth0", on_alert=on_alert, dry_run=True)
  detector.start()
  # ... later when you want to stop:
  detector.stop()

Requires: scapy, python-dateutil, requests (optional)
Install: sudo pip3 install scapy python-dateutil requests
Run with root (sniffing & ARP send).
"""

import threading
import time
import subprocess
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from dateutil import tz
from scapy.all import sniff, ARP, Ether, sendp, conf
import requests
import logging

# Defaults
DEFAULT_WINDOW = 60
DEFAULT_CHANGE_THRESHOLD = 2    # farklı MAC sayısı
DEFAULT_MAC_IP_THRESHOLD = 8    # bir MAC'in sahip olduğu farklı IP sayısı (MITM göstergesi)
DEFAULT_RATE_THRESHOLD = 20     # saniyede ARP paketleri (flood)
DEFAULT_CLEANUP = 5

def iso_now():
    return datetime.now(timezone.utc).astimezone(tz.tzlocal()).isoformat()

class ARPDetector:
    """
    ARPDetector: entegre edilebilir ARP poisoning detector.

    Args:
      iface: network interface to sniff.
      on_alert: callback function that will be called with a dict when alert occurs.
      dry_run: if True, do not perform system-level fixes (default True).
      autofix: if True and dry_run False, attempt automatic remediation (gratuitous ARP or arp -s).
      fix_method: "gratuitous" or "static_arp" or "none" (default "gratuitous").
      trusted_map: optional dict of ip->trusted_mac to use as baseline.
      webhook: optional URL string to POST alerts.
      window: sliding window in seconds.
      change_threshold: number of different macs for same ip => alert.
      mac_ip_threshold: number of ips claimed by one mac => alert.
      rate_threshold: arp pkts/sec threshold => alert.
    """
    def __init__(self,
                 iface,
                 on_alert=None,
                 dry_run=True,
                 autofix=False,
                 fix_method="gratuitous",
                 trusted_map=None,
                 webhook=None,
                 window=DEFAULT_WINDOW,
                 change_threshold=DEFAULT_CHANGE_THRESHOLD,
                 mac_ip_threshold=DEFAULT_MAC_IP_THRESHOLD,
                 rate_threshold=DEFAULT_RATE_THRESHOLD,
                 cleanup_interval=DEFAULT_CLEANUP,
                 logger=None):
        self.iface = iface
        self.on_alert = on_alert
        self.dry_run = dry_run
        self.autofix = autofix
        self.fix_method = fix_method
        self.trusted_map = trusted_map or {}
        self.webhook = webhook
        self.window = window
        self.change_threshold = change_threshold
        self.mac_ip_threshold = mac_ip_threshold
        self.rate_threshold = rate_threshold
        self.cleanup_interval = cleanup_interval

        # internal state
        self._ip_history = defaultdict(lambda: deque())   # ip -> deque of (mac, ts)
        self._mac_to_ips = defaultdict(set)              # mac -> set(ips)
        self._recent_arp_times = deque()                 # timestamps of ARP pkts (for rate)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sniffer_thread = None
        self._cleanup_thread = None
        self._logger = logger or logging.getLogger("ARPDetector")
        self._logger.setLevel(logging.INFO)

        # attempt to populate baseline if not provided
        if not self.trusted_map:
            try:
                self.trusted_map = self._get_system_arp_table()
                self._logger.info(f"[ARPDetector] populated trusted_map from system arp: {len(self.trusted_map)} entries")
            except Exception as e:
                self._logger.warning(f"[ARPDetector] failed to populate trusted_map: {e}")

    # -------------------
    # Public API
    # -------------------
    def start(self):
        """Start sniffing and cleanup threads. Non-blocking."""
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            return
        self._stop.clear()
        self._sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._sniffer_thread.start()
        self._cleanup_thread.start()
        self._logger.info(f"[ARPDetector] started on iface {self.iface}")

    def stop(self):
        """Stop threads and sniffing."""
        self._stop.set()
        # Scapy sniff cannot be cleanly stopped from another thread in all versions.
        # We rely on the daemon threads exiting when program ends; to force-stop, use scapy's conf.sniff_promisc False or kill process.
        self._logger.info("[ARPDetector] stopping...")

    def set_whitelist(self, ip_list):
        """Set whitelist - ips ignored by detector."""
        self.whitelist = set(ip_list)

    def get_state_snapshot(self):
        """Return a snapshot of current ip->mac history (for UI)"""
        with self._lock:
            return {ip: list(deq) for ip, deq in self._ip_history.items()}

    # -------------------
    # Internal helpers
    # -------------------
    def _get_system_arp_table(self):
        """Read 'ip neigh' or 'arp -n' to build a baseline ip->mac map. Linux-specific."""
        res = {}
        try:
            out = subprocess.check_output(["ip", "neigh"], universal_newlines=True)
            # lines like: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    ip = parts[0]
                    if "lladdr" in parts:
                        idx = parts.index("lladdr")
                        mac = parts[idx+1]
                        res[ip] = mac.lower()
        except Exception:
            try:
                out = subprocess.check_output(["arp", "-n"], universal_newlines=True)
                # parse arp -n format
                for line in out.splitlines():
                    if line.strip().startswith("Address") or not line.strip():
                        continue
                    cols = line.split()
                    ip = cols[0]
                    mac = cols[2]
                    res[ip] = mac.lower()
            except Exception as e:
                self._logger.warning(f"[ARPDetector] system arp read failed: {e}")
        return res

    def _sniff_loop(self):
        """Start scapy sniff (blocking). We run this in a daemon thread."""
        # bind to iface
        conf.iface = self.iface
        # BPF filter - only ARP
        try:
            sniff(filter="arp", prn=self._packet_callback, store=False)
        except Exception as e:
            self._logger.error(f"[ARPDetector] sniff failed: {e}")

    def _cleanup_loop(self):
        while not self._stop.is_set():
            time.sleep(self.cleanup_interval)
            cutoff = time.time() - self.window
            with self._lock:
                # cleanup ip history older than window
                to_delete = []
                for ip, dq in self._ip_history.items():
                    while dq and dq[0][1] < cutoff:
                        dq.popleft()
                    if not dq:
                        to_delete.append(ip)
                for ip in to_delete:
                    self._ip_history.pop(ip, None)
                # cleanup mac->ips mapping consistent with ip_history
                self._mac_to_ips = defaultdict(set)
                for ip, dq in self._ip_history.items():
                    seen = {entry[0] for entry in dq}
                    for mac in seen:
                        self._mac_to_ips[mac].add(ip)
                # cleanup recent arp times older than 1s window for rate calc
                nowt = time.time()
                while self._recent_arp_times and self._recent_arp_times[0] < nowt - 1.0:
                    self._recent_arp_times.popleft()

    def _packet_callback(self, pkt):
        """Called by scapy for each ARP packet."""
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        src_ip = arp.psrc
        src_mac = arp.hwsrc.lower()
        ts = time.time()
        # record rate
        with self._lock:
            self._recent_arp_times.append(ts)
            self._ip_history[src_ip].append((src_mac, ts))
            # update mac->ips mapping now (we'll rebuild during cleanup too)
            self._mac_to_ips[src_mac].add(src_ip)

        # detection checks (do not hold lock during heavy work)
        try:
            self._check_ip_mac_changes(src_ip)
            self._check_mac_ip_count(src_mac)
            self._check_arp_rate()
        except Exception as e:
            self._logger.exception(f"[ARPDetector] exception in detection checks: {e}")

    def _check_ip_mac_changes(self, ip):
        """If an IP has been observed with multiple different MACs in window -> alert."""
        with self._lock:
            dq = self._ip_history.get(ip, deque())
            macs = {entry[0] for entry in dq}
        if len(macs) >= self.change_threshold:
            # determine trusted mac if available
            trusted = self.trusted_map.get(ip)
            details = {
                "ip": ip,
                "seen_macs": list(macs),
                "trusted_mac": trusted,
                "timestamp": iso_now()
            }
            self._emit_alert("IP_MAC_CONFLICT", details)
            # attempt remediation if allowed
            if self.autofix and not self.dry_run:
                self._attempt_fix(ip, trusted, list(macs))

    def _check_mac_ip_count(self, mac):
        """If a MAC claims many IPs -> potential MITM."""
        with self._lock:
            ips = self._mac_to_ips.get(mac, set())
        if len(ips) >= self.mac_ip_threshold:
            details = {
                "mac": mac,
                "ips": list(ips),
                "count": len(ips),
                "timestamp": iso_now()
            }
            self._emit_alert("MAC_CLAIMS_MANY_IPS", details)
            # optional remediation? usually you'd isolate interface / alert admin

    def _check_arp_rate(self):
        """If ARP packets/sec exceeds threshold -> flood or scanning."""
        with self._lock:
            rate = len(self._recent_arp_times)  # per second approx
        if rate >= self.rate_threshold:
            details = {"rate_per_sec": rate, "timestamp": iso_now()}
            self._emit_alert("ARP_RATE_HIGH", details)

    def _emit_alert(self, reason, details):
        alert = {
            "time": iso_now(),
            "reason": reason,
            "details": details
        }
        msg = json.dumps(alert, ensure_ascii=False)
        self._logger.warning(msg)
        # callback
        if callable(self.on_alert):
            try:
                self.on_alert(alert)
            except Exception as e:
                self._logger.exception(f"[ARPDetector] on_alert callback raised: {e}")
        # webhook
        if self.webhook:
            try:
                requests.post(self.webhook, json=alert, timeout=5)
            except Exception as e:
                self._logger.warning(f"[ARPDetector] webhook failed: {e}")

    # -------------------
    # Remediation helpers
    # -------------------
    def _attempt_fix(self, ip, trusted_mac, seen_macs):
        """Try to remediate. Two methods:
            - gratuitous: send gratuitous ARP with trusted_mac (or current system mapping)
            - static_arp: run 'arp -s ip mac' to write static mapping (requires root)
        """
        if self.fix_method == "none":
            return
        # pick mac to restore: trusted_map > system arp > first seen
        chosen = trusted_mac
        if not chosen:
            # try system ARP
            sysmap = {}
            try:
                sysmap = self._get_system_arp_table()
            except Exception:
                pass
            chosen = sysmap.get(ip)
        if not chosen:
            chosen = seen_macs[0] if seen_macs else None
        if not chosen:
            self._logger.warning(f"[ARPDetector] no candidate mac to fix for {ip}")
            return

        self._logger.info(f"[ARPDetector] attempting fix for {ip} -> {chosen} using method {self.fix_method}")

        if self.fix_method == "gratuitous":
            self._send_gratuitous_arp(ip, chosen)
        elif self.fix_method == "static_arp":
            self._add_static_arp(ip, chosen)

    def _send_gratuitous_arp(self, ip, mac):
        """Send gratuitous ARP (ARP reply claiming ip->mac) on interface."""
        try:
            if self.dry_run:
                self._logger.info(f"[ARPDetector] dry-run: would send gratuitous ARP for {ip} -> {mac}")
                return
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(op=2, psrc=ip, hwsrc=mac, pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
            pkt = ether/arp
            sendp(pkt, iface=self.iface, verbose=False, count=3)
            self._logger.info(f"[ARPDetector] sent gratuitous ARP for {ip} -> {mac}")
        except Exception as e:
            self._logger.exception(f"[ARPDetector] gratuitous arp failed: {e}")

    def _add_static_arp(self, ip, mac):
        """Add static ARP entry via 'arp -s'. Requires root."""
        try:
            if self.dry_run:
                self._logger.info(f"[ARPDetector] dry-run: would run: arp -s {ip} {mac}")
                return
            subprocess.check_call(["arp", "-s", ip, mac])
            self._logger.info(f"[ARPDetector] added static arp {ip} -> {mac}")
        except Exception as e:
            self._logger.exception(f"[ARPDetector] add static arp failed: {e}")
