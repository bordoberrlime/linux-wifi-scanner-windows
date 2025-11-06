#!/usr/bin/env python3

# Basit WiFi tarayıcı (Scapy kullanır)
# Not: Bu araç Linux için tasarlanmıştır (monitor mode gerektirir). Windows'ta çalıştırmak için 
# kablosuz adaptörünüzün Windows'ta monitor mode desteklemesi ve Scapy ile uyumlu olması gerekir.
# Bu paket eğitim amaçlıdır. İzinsiz kullanım yasadışıdır.
import argparse
import time
import sys
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
except Exception as e:
    print("[!] Scapy veya gerekli katmanlar yüklenmemiş olabilir:", e)
    print("    Windows'ta scapy kurulumu ve kablosuz sürücü desteği sınırlı olabilir.")
    sys.exit(1)

def parse_packet(pkt, networks):
    # Beacon veya Probe Response/Request
    if pkt.haslayer(Dot11):
        # type 0 = management, subtype 8 = beacon, 5 = probe response, 4 = probe request
        if pkt.type == 0 and (pkt.subtype == 8 or pkt.subtype == 5 or pkt.subtype == 4):
            bssid = pkt.addr2
            if bssid is None:
                return

            ssid = "<hidden>"
            channel = None
            crypto = set()
            signal = None

            # RSSI (RadioTap)
            try:
                if pkt.haslayer(RadioTap) and hasattr(pkt.getlayer(RadioTap), 'dBm_AntSignal'):
                    signal = pkt.getlayer(RadioTap).dBm_AntSignal
            except Exception:
                signal = None

            # Dot11Elts parsing
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 0:
                        try:
                            ssid = elt.info.decode(errors='ignore') or "<hidden>"
                        except Exception:
                            ssid = "<hidden>"
                    elif elt.ID == 3:
                        try:
                            # elt.info is a single byte for channel in many frames
                            channel = elt.info[0] if len(elt.info) else None
                        except Exception:
                            channel = None
                    elif elt.ID == 48:
                        crypto.add('WPA2')
                    elif elt.ID == 221:
                        info = elt.info
                        if b"WPA" in info or b"wpa" in info:
                            crypto.add('WPA')
                    elt = elt.payload

            # Capability privacy bit check (simple heuristic)
            try:
                cap = pkt.sprintf("%Dot11Beacon.cap%")
                if 'privacy' in cap.lower():
                    crypto.add('WEP/WPA?')
            except Exception:
                pass

            if not crypto:
                crypto.add('OPEN')

            now = datetime.now()
            networks[bssid]['ssid'] = ssid
            networks[bssid]['channel'] = channel
            networks[bssid]['crypto'] = ",".join(sorted(list(crypto)))
            networks[bssid]['signal'] = signal
            networks[bssid]['last_seen'] = now

def print_table(networks):
    # Clear terminal (cross-platform escape)
    sys.stdout.write('\x1b[2J\x1b[H')
    print(f"WiFi Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("{:<20} {:<32} {:<7} {:<8} {:<20} {:<6}".format('BSSID','SSID','CHAN','SIGNAL','CRYPTO','AGE'))
    print('-'*110)
    for bssid, info in sorted(networks.items(), key=lambda x: (x[1].get('signal') or -999), reverse=True):
        ssid = info.get('ssid','')[:30]
        chan = info.get('channel') or '-'
        sig = info.get('signal') if info.get('signal') is not None else '-'
        crypto = info.get('crypto','')
        last = info.get('last_seen')
        age = f"{int((datetime.now()-last).total_seconds())}s" if last else ''
        print(f"{bssid:<20} {ssid:<32} {str(chan):<7} {str(sig):<8} {crypto:<20} {age:<6}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', required=True, help='monitor mode interface (e.g. wlan0mon). Windows: may be different or unsupported')
    parser.add_argument('--timeout', type=int, default=0, help='timeout seconds (0 = infinite)')
    args = parser.parse_args()

    networks = defaultdict(dict)

    print('[*] Başlatılıyor... (Ctrl+C ile durdur)')

    def pkt_handler(pkt):
        try:
            parse_packet(pkt, networks)
        except Exception:
            pass

    try:
        if args.timeout and args.timeout > 0:
            sniff(iface=args.iface, prn=pkt_handler, timeout=args.timeout)
        else:
            sniff(iface=args.iface, prn=pkt_handler, store=0)
    except PermissionError:
        print('[!] Root / Yönetici yetkisi gerekebilir. Windows'ta yönetici olarak çalıştırın.')
        sys.exit(1)
    except Exception as e:
        print(f'[!] Hata: {e}')
        sys.exit(1)

if __name__ == '__main__':
    # Print loop in main thread
    import threading
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--iface', required=True)
    parser.add_argument('--timeout', type=int, default=0)
    args, _ = parser.parse_known_args()

    networks = defaultdict(dict)
    stop_event = threading.Event()

    def run_sniff():
        try:
            sniff(iface=args.iface, prn=lambda p: parse_packet(p, networks), store=0, timeout=args.timeout if args.timeout>0 else None)
        except Exception as e:
            print('[!] Sniff error:', e)
            stop_event.set()

    t = threading.Thread(target=run_sniff, daemon=True)
    t.start()

    try:
        while not stop_event.is_set():
            print_table(networks)
            time.sleep(2)
    except KeyboardInterrupt:
        print('\n[!] Durduruldu.')
        stop_event.set()
        sys.exit(0)
