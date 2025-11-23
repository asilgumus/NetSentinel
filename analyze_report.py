# Gerekli kütüphaneler
from scapy.all import sniff
import threading
import time
from collections import Counter
from colorama import init, Fore
import psutil


init(autoreset=True)

protocol_counts = Counter()


DISPLAY_INTERVAL = 2 

bandwidth_bytes = 0
lock = threading.Lock() # Birden fazla thread'in aynı anda 'bandwidth_bytes'a yazmasını engeller

# --- Çekirdek Fonksiyonlar ---

def packet_callback(packet):
    
    print("--- Anlık Bant Genişliği Monitörü Başlatılıyor ---")
    print("Ağ trafiği dinleniyor... Çıkmak için Ctrl+C.")
    global bandwidth_bytes
    # 'lock' kullanarak, sayaç güncellenirken başka bir işlemin araya girmesini engelliyoruz.
    with lock:
        bandwidth_bytes += len(packet)

def display_bandwidth():
    """
    Arka planda sürekli çalışarak anlık ağ kullanımını hesaplar ve kullanıcıya gösterir.
    Bu fonksiyon kendi thread'inde çalışır.
    """
    global bandwidth_bytes
    
    while True:
        # Belirlenen aralık kadar bekleyerek işlemciyi yormayız.
        time.sleep(DISPLAY_INTERVAL)
        
        # 'lock' ile o anki byte sayısını güvenli bir şekilde alıp, sayacı sıfırlıyoruz.
        with lock:
            bytes_transferred = bandwidth_bytes
            bandwidth_bytes = 0 

        # --- Hesaplama ---
        
        bits_per_second = (bytes_transferred * 8) / DISPLAY_INTERVAL
        
        # --- Formatlama ---
        if bits_per_second < 1000**2:
            formatted_speed = f"{bits_per_second / 1000:.2f} Kbps"
        elif bits_per_second < 1000**3:
            formatted_speed = f"{bits_per_second / 1000**2:.2f} Mbps"
        else:
            formatted_speed = f"{bits_per_second / 1000**3:.2f} Gbps"

        # --- Ekrana Yazdırma ---
        print(Fore.GREEN + f"\rAnlık Ağ Kullanımı: {formatted_speed:<20}", end="")



    # 'display_bandwidth' fonksiyonunu arkaplanda çalışacak bir thread olarak başlatıyoruz.

proto_map = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IP-in-IP",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    41: "IPv6",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    59: "No Next Header",
    89: "OSPF",
    94: "IPIP",
    103: "PIM",
    108: "IPV6-ICMP",
    112: "VRRP",
    115: "L2TP",
    132: "SCTP",
    133: "FC",
    135: "MS RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    254: "Reserved",
    255: "Reserved"
}

def protocol_distribution(paket_sayisi, arayuz=None):
    """
    Ağ trafiğini dinleyip protokol dağılımını hesaplar.

    :param paket_sayisi: Kaç paket dinlenecek (varsayılan 100)
    :param arayuz: Hangi ağ arayüzünde dinlenecek (örn. 'eth0', None ise varsayılan)
    """
    protocol_counts = Counter()
    

    def analyze(packet):
        if packet.haslayer("IP"):
            proto_num = packet["IP"].proto
            protocol_counts[proto_num] += 1

    print(f"{arayuz or 'varsayılan arayüz'} üzerinde {paket_sayisi} paket dinleniyor...")
    sniff(count=paket_sayisi, prn=analyze, iface=arayuz)

    total = sum(protocol_counts.values())
    print("\nProtokol Dağılımı:")
    for proto_num, count in protocol_counts.items():
        name = proto_map.get(proto_num, f"Diğer({proto_num})")
        yüzde = (count / total) * 100
        print(f"{name}: {count} paket ({yüzde:.2f}%)")



def top_talkers(paket_sayisi, arayuz=None):
    protocol_counts = Counter()
    
    def analyze(packet):
        if packet.haslayer("IP"):
            proto_num = packet["IP"].proto
            protocol_counts[proto_num] += 1

    print(f"{arayuz or 'varsayılan arayüz'} üzerinde {paket_sayisi} paket dinleniyor...")
    sniff(count=paket_sayisi, prn=analyze, iface=arayuz)

    total = sum(protocol_counts.values())
    print("\n Top Talkers:")
    for proto_num, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
        name = proto_map.get(proto_num, f"Diğer({proto_num})")
        yüzde = (count / total) * 100
        print(f"{name}: {count} paket ({yüzde:.2f}%)")

def active_connections():
    for conn in psutil.net_connections():
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        print(f"{conn.type}  {conn.status}  {laddr}  -->  {raddr}")

