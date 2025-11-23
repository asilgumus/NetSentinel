from scapy.all import sniff
# from incoming_package import gelen_paket
# from net_traffic import traffic
# from outgoing_package import giden_paket
from net_watch import gelen_paket, giden_paket, traffic
from colorama import Fore, init, Style
from analyze_report import packet_callback, protocol_distribution, top_talkers, active_connections
from security import NetworkProtector
import port_search
from arp_detector import ARPDetector
from dns_monitor_module import DNSMonitor

import time

init(autoreset=True)
while True:
    print("\n\n\n\n")
    print(Fore.GREEN + "--- Ağ İzleme ve Analiz Aracı ---")
    print(Fore.GREEN + "\n[1] Canlı Trafik İzleme")
    print(Fore.GREEN + "  11) Tüm Paketleri İzle")
    print(Fore.GREEN + "  12) Sadece Giden Paketleri İzle")
    print(Fore.GREEN + "  13) Sadece Gelen Paketleri İzle")
    print(Fore.YELLOW  + "***************************************")
    print(Fore.GREEN + "\n[2] Ağ Analizi ve Raporlama")
    print(Fore.GREEN + "  21) Anlık Bant Genişliği Kullanımı")
    print(Fore.GREEN + "  22) Protokol Dağılımını Göster")
    print(Fore.GREEN + "  23) En Çok Trafik Yaratan IP'ler (Top Talkers)")
    print(Fore.GREEN + "  24) Aktif Bağlantıları Listele")
    print(Fore.YELLOW + "***************************************")
    print(Fore.GREEN + "\n[3] Güvenlik Analizi")
    print(Fore.GREEN + "  31) DoS/DDoS/Flood Atağı Kontrolü")
    print(Fore.GREEN + "  32) Port Tarama Girişimlerini Tespit Et")
    print(Fore.GREEN + "  33) ARP Zehirlenmesi Tespiti")
    print(Fore.GREEN + "  34) Şüpheli DNS Sorgularını İzle")
    secim = input(Fore.MAGENTA + "Hangi işlemi yapmak istersiniz: " + Style.RESET_ALL)

    if secim == "11":
        sniff(prn=traffic, filter="ip",store=False)
    elif secim == "12":
        sniff(prn=giden_paket, filter="ip", store=False)
    elif secim == "13":
        sniff(prn=gelen_paket, filter="ip", store=False)
    elif secim == "21":
        try:
            sniff(prn=packet_callback, store=0)
        except KeyboardInterrupt:
            # Kullanıcı Ctrl+C'ye bastığında programı temiz bir şekilde sonlandırır.
            print("\n\nProgram sonlandırılıyor...")
        except Exception as e:
            # Olası bir hata durumunda kullanıcıyı bilgilendirir.
            print(f"\n[KRİTİK HATA] Bir hata oluştu: {e}")
            print("Lütfen programı yönetici olarak çalıştırdığınızdan ve WinPcap/Npcap'in kurulu olduğundan emin olun.")
    elif secim == "22":
        count = int(input("Kaç tane paketi kontrol etmek istersiniz? "))
        protocol_distribution(count)
    elif secim == "23":
        count = int(input("Kaç tane paketi kontrol etmek istersiniz? "))
        top_talkers(count)
    elif secim == "24":
        print(Fore.LIGHTBLUE_EX + f"Aktif Bağlantılar Listelenliyor:")
        print("Bağlantı Türü | Bağlantı Durumu | Adres Türü")
        active_connections()
    elif secim == "31":
        print("[BİLGİ] Ağ koruma sistemi hazırlanıyor...")
        
        # ADIM 1: Sınıftan bir NESNE oluştur (parantezler en önemlisi!)
        my_protector = NetworkProtector()
        
        try:
            # ADIM 2: Korumayı başlat. Bu, arka planda dinlemeyi başlatır.
            my_protector.start()
            
            # ADIM 3: Programın hemen kapanmaması için ana thread'i burada sonsuza kadar beklet.
            # Kullanıcı Ctrl+C'ye bastığında bu döngü kırılacak.
            print("\n[BİLGİ] Koruma aktif. Durdurmak için Ctrl+C'ye basın.")
            while True:
                time.sleep(1) # İşlemciyi yormamak için her saniye bekle
                
        except KeyboardInterrupt:
            # Ctrl+C'ye basıldığında burası çalışır. Hiçbir şey yapmaya gerek yok,
            # program doğal olarak 'finally' bloğuna geçecektir.
            print("\n[BİLGİ] Durdurma isteği algılandı...")
            
        except Exception as e:
            print(f"\n[HATA] Beklenmedik bir hata oluştu: {e}")
            
        finally:
            # ADIM 4: Program her ne sebeple biterse bitsin, sistemi güvenli bir şekilde kapat.
            print("[BİLGİ] Koruma sistemi durduruluyor.")
            my_protector.stop()
    elif secim == "32":
        print(Fore.GREEN + f"Çalıştırılıyor")
        port_search.main()
    elif secim == "33":
        print(Fore.GREEN + "Çalıştırılıyor")
        detector = ARPDetector(
            iface="eth0",
            on_alert=None,
            dry_run=True,          
            autofix=False,
            fix_method="gratuitous",
            webhook=None
        )
        detector.start()
        print("ARPDetector çalışıyor (test modunda). 120s sonra durdurulacak.")
        try:
            time.sleep(120)
        except KeyboardInterrupt:
            pass
        detector.stop()
        print("Detektor durduruldu.")
    elif secim == "34":
        monitor = DNSMonitor(
        iface="eth0",
        on_alert=None,
        dry_run=True,
        blacklist=["bad.com","malware.test"]
    )
        monitor.start()
        print("DNSMonitor çalışıyor...")
        try:
            time.sleep(120)  # test için 2dk çalışsın
        except KeyboardInterrupt:
            pass
        monitor.stop()
        print("DNSMonitor durduruldu.")


        
    else:
        print("Geçersiz seçim")
