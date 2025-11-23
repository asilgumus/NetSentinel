# Gerekli kütüphaneler
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
from colorama import init, Fore, Style
import os
import threading
import statistics

# Renkleri her print sonrası sıfırlamak için
init(autoreset=True)

class NetworkProtector:
    """
    Ağ trafiğini analiz ederek DDoS, DoS ve Flood saldırılarını tespit eden 
    ve isteğe bağlı olarak engelleyen bir ağ koruma sistemi sınıfı.
    """
    def __init__(self,
                 learning_duration=60,
                 window_size=5,
                 baseline_multiplier=2.5,
                 auto_block_dos=False,
                 auto_block_ddos=True,
                 temp_block_duration=300):
        
        print(Fore.CYAN + "--- Gelişmiş Ağ Koruma Sistemi Sınıfı Başlatılıyor ---")

        self.LEARNING_MODE_DURATION = learning_duration
        self.WINDOW_SIZE = window_size
        self.BASELINE_MULTIPLIER = baseline_multiplier
        self.AUTO_BLOCK_DOS = auto_block_dos
        self.AUTO_BLOCK_DDoS = auto_block_ddos
        self.TEMP_BLOCK_DURATION = temp_block_duration

        # --- Eşik Değerleri ---
        self.THRESHOLD_GENERAL_PACKETS = 2000
        self.THRESHOLD_DOS_PACKETS = 250
        self.THRESHOLD_DDOS_PACKETS = 500
        self.THRESHOLD_SYN_FLOOD_RATIO = 0.60  # Eşikleri biraz daha esnek hale getirelim
        self.THRESHOLD_UDP_FLOOD_RATIO = 0.60
        self.THRESHOLD_ICMP_FLOOD_RATIO = 0.60
        self.HTTP_PORTS = {80, 443}
        self.HTTP_FLOOD_THRESHOLD_PER_IP = 50
        
        # <<< ÖNEMLİ DEĞİŞİKLİK: Yanlış alarmları önlemek için daha yüksek bir alt limit
        self.MIN_TOTAL_PACKETS_FOR_ANALYSIS = 250 

        # --- Durum Değişkenleri ---
        self.blocked_ips = set()
        self.temp_blocked_ips = {}
        self.lock = threading.Lock()
        self.ip_packet_counts = defaultdict(int)
        self.protocol_counts = defaultdict(int)
        self.syn_count = 0
        self.http_request_counts = defaultdict(int)
        self.is_running = False
        self.sniffer_thread = None
        self.analyzer_thread = None
        self.temp_block_thread = None

    # _block_ip, _unblock_ip, _check_temp_blocks ve _packet_callback metotları aynı kalabilir...
    # (Bu metotlarda bir değişiklik gerekmediği için tekrar eklemiyorum, kodunuzda olduğu gibi bırakın)
    def _block_ip(self, ip_address, is_temp=False):
        if ip_address not in self.blocked_ips:
            try:
                os.system(f'netsh advfirewall firewall add rule name="Block_Attack_{ip_address}" dir=in action=block remoteip={ip_address}')
                self.blocked_ips.add(ip_address)
                with open("blocked_ips.log", "a") as file:
                    file.write(f"[{time.ctime()}] BLOCKED: {ip_address}\n")
                print(Fore.RED + f"[ENGELLEDİ] {ip_address} güvenlik duvarı tarafından engellendi.")
                if is_temp:
                    self.temp_blocked_ips[ip_address] = time.time()
                    print(Fore.YELLOW + f"[GEÇİCİ ENGEL] {ip_address}, {self.TEMP_BLOCK_DURATION} saniyeliğine engellendi.")
            except Exception as e:
                print(Fore.RED + f"[HATA] {ip_address} engellenirken hata: {e}")
        else:
            print(Fore.YELLOW + f"[BİLGİ] {ip_address} zaten engellenmiş durumda.")

    def _unblock_ip(self, ip_address):
        if ip_address in self.blocked_ips:
            try:
                os.system(f'netsh advfirewall firewall delete rule name="Block_Attack_{ip_address}"')
                self.blocked_ips.remove(ip_address)
                if ip_address in self.temp_blocked_ips:
                    del self.temp_blocked_ips[ip_address]
                with open("blocked_ips.log", "a") as file:
                    file.write(f"[{time.ctime()}] UNBLOCKED: {ip_address}\n")
                print(Fore.GREEN + f"[ENGEL KALDIRILDI] {ip_address} için engel kaldırıldı.")
            except Exception as e:
                print(Fore.RED + f"[HATA] {ip_address} engeli kaldırılırken hata: {e}")

    def _check_temp_blocks(self):
        while self.is_running:
            current_time = time.time()
            with self.lock:
                ips_to_unblock = [ip for ip, block_time in self.temp_blocked_ips.items() if current_time - block_time > self.TEMP_BLOCK_DURATION]
            
            for ip in ips_to_unblock:
                self._unblock_ip(ip)
            time.sleep(30)

    def _packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            if src_ip in self.blocked_ips: return

            with self.lock:
                self.ip_packet_counts[src_ip] += 1
                if TCP in packet:
                    self.protocol_counts['TCP'] += 1
                    if packet[TCP].flags == 'S':
                        self.syn_count += 1
                    if packet[TCP].dport in self.HTTP_PORTS and packet.haslayer('Raw'):
                        if packet.getlayer('Raw').load.startswith(b'GET /'):
                            self.http_request_counts[src_ip] += 1
                elif UDP in packet:
                    self.protocol_counts['UDP'] += 1
                elif ICMP in packet:
                    self.protocol_counts['ICMP'] += 1
                else:
                    self.protocol_counts['OTHER'] += 1


    def _analyze_and_protect(self):
        while self.is_running:
            time.sleep(self.WINDOW_SIZE)
            with self.lock:
                current_ip_counts = self.ip_packet_counts.copy()
                current_protocol_counts = self.protocol_counts.copy()
                current_syn_count = self.syn_count
                current_http_counts = self.http_request_counts.copy()
                
                self.ip_packet_counts.clear()
                self.protocol_counts.clear()
                self.syn_count = 0
                self.http_request_counts.clear()
            
            total_packets = sum(current_protocol_counts.values())
            print(Style.DIM + f"Geçen {self.WINDOW_SIZE} saniyede analiz edilen toplam paket: {total_packets}")

            if total_packets < self.MIN_TOTAL_PACKETS_FOR_ANALYSIS:
                continue

            # <<< YENİ MANTIK: ÖNCE HACİMSEL SALDIRI TESPİTİ, SONRA TİPİNİ BELİRLEME <<<
            is_volumetric_attack = total_packets > self.THRESHOLD_GENERAL_PACKETS
            
            if is_volumetric_attack:
                attack_type = "Bilinmeyen Tip"
                
                # Hacimsel saldırı varsa, şimdi tipini anlamak için oranları kontrol et
                total_tcp = current_protocol_counts.get('TCP', 0)
                total_udp = current_protocol_counts.get('UDP', 0)
                total_icmp = current_protocol_counts.get('ICMP', 0)

                # TCP SYN Flood kontrolü
                if total_tcp > 0 and (current_syn_count / total_tcp) >= self.THRESHOLD_SYN_FLOOD_RATIO:
                    attack_type = f"TCP SYN Flood (SYN Oranı: %{100*current_syn_count/total_tcp:.1f})"
                
                # UDP Flood kontrolü
                elif total_udp > 0 and (total_udp / total_packets) >= self.THRESHOLD_UDP_FLOOD_RATIO:
                    attack_type = f"UDP Flood (UDP Oranı: %{100*total_udp/total_packets:.1f})"
                
                # ICMP Flood kontrolü
                elif total_icmp > 0 and (total_icmp / total_packets) >= self.THRESHOLD_ICMP_FLOOD_RATIO:
                    attack_type = f"ICMP Flood (ICMP Oranı: %{100*total_icmp/total_packets:.1f})"
                
                print(Fore.MAGENTA + Style.BRIGHT + f"\n!!! TEHLİKE: HACİMSEL SALDIRI TESPİT EDİLDİ !!!")
                print(Fore.MAGENTA + f"  -> Toplam Paket: {total_packets} (Eşik: {self.THRESHOLD_GENERAL_PACKETS})")
                print(Fore.MAGENTA + f"  -> Saldırı Tipi: {attack_type}")

            # IP bazlı kontroller (DoS, gürültücü botlar) her zaman yapılır
            for ip, count in current_http_counts.items():
                if count > self.HTTP_FLOOD_THRESHOLD_PER_IP:
                    print(Fore.CYAN + Style.BRIGHT + f"\n!!! UYARI: POTANSİYEL HTTP GET FLOOD ({ip} -> {count} istek)")
                    if self.AUTO_BLOCK_DOS: self._block_ip(ip, is_temp=True)

            for ip, count in current_ip_counts.items():
                if count > self.THRESHOLD_DDOS_PACKETS:
                    print(Fore.YELLOW + Style.BRIGHT + f"\nUYARI: YÜKSEK HACİMLİ KAYNAK (DDoS Bot?) TESPİT EDİLDİ ({ip} -> {count} paket)")
                    if self.AUTO_BLOCK_DDoS: self._block_ip(ip, is_temp=False)
                elif count > self.THRESHOLD_DOS_PACKETS:
                    print(Fore.YELLOW + Style.BRIGHT + f"\nUYARI: YÜKSEK HACİMLİ KAYNAK (DoS?) TESPİT EDİLDİ ({ip} -> {count} paket)")
                    if self.AUTO_BLOCK_DOS: self._block_ip(ip, is_temp=True)

    # _run_learning_mode ve diğer metotlar...
    def _run_learning_mode(self):
        print(Fore.YELLOW + f"\n[ÖĞRENME MODU] Normal ağ trafiği {self.LEARNING_MODE_DURATION} saniye boyunca analiz ediliyor...")
        learning_packets_per_window = []
        
        self.temp_packet_count = 0
        def learning_callback(packet):
            self.temp_packet_count += 1
        
        sniffer_learning_thread = threading.Thread(target=lambda: sniff(prn=learning_callback, store=0, timeout=self.LEARNING_MODE_DURATION))
        sniffer_learning_thread.start()
        
        start_time = time.time()
        last_capture_time = start_time
        
        while sniffer_learning_thread.is_alive():
            elapsed = time.time() - start_time
            print(f"\r  Öğrenme süresi: {int(elapsed)}/{self.LEARNING_MODE_DURATION} saniye...", end="")
            
            if time.time() - last_capture_time >= self.WINDOW_SIZE:
                 learning_packets_per_window.append(self.temp_packet_count)
                 self.temp_packet_count = 0
                 last_capture_time = time.time()
            time.sleep(0.5)
        
        if len(learning_packets_per_window) > 1: # İstatistiksel anlamlılık için en az 2 veri noktası
            avg_packets = statistics.mean(learning_packets_per_window)
            std_dev_packets = statistics.stdev(learning_packets_per_window)
            dynamic_threshold = avg_packets + (std_dev_packets * self.BASELINE_MULTIPLIER)
            self.THRESHOLD_GENERAL_PACKETS = int(dynamic_threshold)
            
            MINIMUM_SAFE_THRESHOLD = 500
            if self.THRESHOLD_GENERAL_PACKETS < MINIMUM_SAFE_THRESHOLD:
                print(Fore.YELLOW + f"\n[UYARI] Dinamik eşik ({self.THRESHOLD_GENERAL_PACKETS}) çok düşük. Güvenli minimum ({MINIMUM_SAFE_THRESHOLD}) kullanılacak.")
                self.THRESHOLD_GENERAL_PACKETS = MINIMUM_SAFE_THRESHOLD

            print(Fore.GREEN + "\n\n[ÖĞRENME TAMAMLANDI]")
            print(f"  Ortalama Trafik: {avg_packets:.2f} paket / {self.WINDOW_SIZE} saniye")
            print(f"  Dinamik Hacimsel Saldırı Eşiği {Fore.GREEN+Style.BRIGHT}{self.THRESHOLD_GENERAL_PACKETS}{Style.RESET_ALL} olarak ayarlandı.")
        else:
            print(Fore.RED + "\n[ÖĞRENME BAŞARISIZ] Yeterli trafik veya veri noktası alınamadı. Statik eşiklerle devam ediliyor.")

    def _run_sniffer(self):
        print(Fore.GREEN + Style.BRIGHT + "[KORUMA MODU AKTİF] Ağ dinleniyor...")
        try:
            sniff(prn=self._packet_callback, store=0, stop_filter=lambda p: not self.is_running)
        except Exception as e:
            print(f"\n[KRİTİK HATA] Sniffer durdu: {e}")
            print("Lütfen yönetici olarak çalıştırdığınızdan ve WinPcap/Npcap'in kurulu olduğundan emin olun.")
            self.is_running = False

    def start(self):
        if self.is_running:
            print(Fore.YELLOW + "Sistem zaten çalışıyor.")
            return
        self.is_running = True
        self._run_learning_mode()
        print("\n--- Yapılandırma Bilgileri ---")
        print(f"  Analiz Penceresi: {self.WINDOW_SIZE} sn")
        print(f"  Hacimsel Eşik: {self.THRESHOLD_GENERAL_PACKETS} paket")
        print(f"  IP DoS/DDoS Eşikleri: {self.THRESHOLD_DOS_PACKETS}/{self.THRESHOLD_DDOS_PACKETS} paket")
        print(f"  SYN/UDP/ICMP Oran Eşikleri: %{int(self.THRESHOLD_SYN_FLOOD_RATIO*100)} / %{int(self.THRESHOLD_UDP_FLOOD_RATIO*100)} / %{int(self.THRESHOLD_ICMP_FLOOD_RATIO*100)}")
        print("--------------------------------\n")
        self.analyzer_thread = threading.Thread(target=self._analyze_and_protect, daemon=True)
        self.temp_block_thread = threading.Thread(target=self._check_temp_blocks, daemon=True)
        self.sniffer_thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self.analyzer_thread.start()
        self.temp_block_thread.start()
        self.sniffer_thread.start()
        print("Tüm koruma servisleri başlatıldı.")

    def stop(self):
        if not self.is_running:
            print(Fore.YELLOW + "Sistem zaten durdurulmuş.")
            return
        print("\n" + Fore.CYAN + "--- Koruma Sistemi Durduruluyor... ---")
        self.is_running = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
             self.sniffer_thread.join(timeout=2)
        if self.analyzer_thread and self.analyzer_thread.is_alive():
             self.analyzer_thread.join(timeout=self.WINDOW_SIZE + 1)
        if self.temp_block_thread and self.temp_block_thread.is_alive():
             self.temp_block_thread.join(timeout=2)
        print(Fore.GREEN + "Sistem başarıyla durduruldu.")