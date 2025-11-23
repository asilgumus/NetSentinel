from scapy.all import sniff, TCP, UDP, IP, ICMP
import socket

hostname = socket.gethostname()
ipv4_address = socket.gethostbyname(hostname)



proto_dict = {
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





# TCP/UDP port → uygulama protokolü
port_dict = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    194: "IRC",
    443: "HTTPS",
    445: "Microsoft-DS",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP-Submission",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2483: "Oracle-DB",
    2484: "Oracle-DB-SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9000: "SonarQube",
    9090: "HTTP-Alt2",
    10000: "Webmin",
    27017: "MongoDB",
    50000: "SAP"
}





def gelen_paket(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        # Sadece gelen paketler
        if ip_layer.dst == ipv4_address:
            proto_name = proto_dict.get(ip_layer.proto, "Diğer")
            
            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                src_proto = port_dict.get(sport, "Diğer")
                dst_proto = port_dict.get(dport, "Diğer")
                app_proto = f"SrcPort: {src_proto} | DstPort: {dst_proto}"
            elif packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                src_proto = port_dict.get(sport, "Diğer")
                dst_proto = port_dict.get(dport, "Diğer")
                app_proto = f"SrcPort: {src_proto} | DstPort: {dst_proto}"
            elif packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                app_proto = f"ICMP Type: {icmp_type}, Code: {icmp_code}"
            else:
                app_proto = "Diğer"

            print(f"Gelen Paket | Kaynak IP: {ip_layer.src} | Hedef IP: {ip_layer.dst} | TTL: {ip_layer.ttl} | IP Proto: {ip_layer.proto} ({proto_name}) | Uygulama Proto: {app_proto}")





def giden_paket(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        
        # Sadece giden paketler
        if ip_layer.src == ipv4_address:
            # IP protokolünü isimle göster
            proto_name = proto_dict.get(ip_layer.proto, "Diğer")
            
            # TCP veya UDP ise port bazlı uygulama protokolünü bul
            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                src_proto = port_dict.get(sport, "Diğer")
                dst_proto = port_dict.get(dport, "Diğer")
                app_proto = f"SrcPort: {src_proto} | DstPort: {dst_proto}"
            elif packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                src_proto = port_dict.get(sport, "Diğer")
                dst_proto = port_dict.get(dport, "Diğer")
                app_proto = f"SrcPort: {src_proto} | DstPort: {dst_proto}"
            elif packet.haslayer(ICMP):
                # ICMP için uygulama protokolü yok, sadece tip ve kod gösterebilirsiniz
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                app_proto = f"ICMP Type: {icmp_type}, Code: {icmp_code}"
            else:
                app_proto = "Diğer"

            print(f"Giden Paket | Kaynak IP: {ip_layer.src} | Hedef IP: {ip_layer.dst} | TTL: {ip_layer.ttl} | IP Proto: {ip_layer.proto} ({proto_name}) | Uygulama Proto: {app_proto}")








def traffic(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        if ip_layer.dst == ipv4_address:
            proto_name = proto_dict.get(ip_layer.proto, "Diğer")
            
            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                src_proto = port_dict.get(sport, "Diğer")
                dst_proto = port_dict.get(dport, "Diğer")
                app_proto = f"SrcPort: {src_proto} | DstPort: {dst_proto}"
            elif packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                src_proto = port_dict.get(sport, "Diğer")
                dst_proto = port_dict.get(dport, "Diğer")
                app_proto = f"SrcPort: {src_proto} | DstPort: {dst_proto}"
            elif packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                app_proto = f"ICMP Type: {icmp_type}, Code: {icmp_code}"
            else:
                app_proto = "Diğer"

            print(f"Gelen Paket | Kaynak IP: {ip_layer.src} | Hedef IP: {ip_layer.dst} | TTL: {ip_layer.ttl} | IP Proto: {ip_layer.proto} ({proto_name}) | Uygulama Proto: {app_proto} | Paket Boyutu: {len(packet)} byte | Zaman Damgası: {packet.time}")
        elif ip_layer.src == ipv4_address:
            # IP protokolünü isimle göster
            proto_name = proto_dict.get(ip_layer.proto, "Diğer")
            
            # TCP veya UDP ise port bazlı uygulama protokolünü bul
            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                src_proto = port_dict.get(sport, "Diğer")
                dst_proto = port_dict.get(dport, "Diğer")
                app_proto = f"SrcPort: {src_proto} | DstPort: {dst_proto}"
            elif packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                src_proto = port_dict.get(sport, "Diğer")
                dst_proto = port_dict.get(dport, "Diğer")
                app_proto = f"SrcPort: {src_proto} | DstPort: {dst_proto}"
            elif packet.haslayer(ICMP):
                # ICMP için uygulama protokolü yok, sadece tip ve kod gösterebilirsiniz
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                app_proto = f"ICMP Type: {icmp_type}, Code: {icmp_code}"
            else:
                app_proto = "Diğer"

            print(f"Giden Paket | Kaynak IP: {ip_layer.src} | Hedef IP: {ip_layer.dst} | TTL: {ip_layer.ttl} | IP Proto: {ip_layer.proto} ({proto_name}) | Uygulama Proto: {app_proto} | Paket Boyutu: {len(packet)} byte | Zaman Damgası: {packet.time}")
