# Linux WiFi Scanner (Windows-ready package)
Bu proje **aslen Linux için tasarlanmış** bir pasif Wi-Fi tarayıcıdır (monitor mode gerektirir).  
İstek üzerine Windows üzerinde kullanmak üzere dosyalar .zip halinde hazırlandı — fakat Windows'ta çalıştırmak için uygun kablosuz sürücü ve scapy desteği gerekebilir.

## İçerik
- `wifi_scan.py` : Ana Python tarayıcı betiği
- `README.md` : Bu dosya
- `requirements.txt` : Python bağımlılıkları
- `.gitignore`
- `LICENSE` (MIT)

## Kullanım (Windows)
1. ZIP'i çıkartın.
2. Python 3.8+ kurun.
3. Komut istemcisini Yönetici olarak çalıştırın (sağ tık -> Run as administrator).
4. Sanal ortam (isteğe bağlı):
   ```
   python -m venv venv
   venv\\Scripts\\activate
   ```
5. Bağımlılıkları kurun:
   ```
   pip install -r requirements.txt
   ```
6. Uygulamayı çalıştırın (örnek):
   ```
   python wifi_scan.py --iface <interface>
   ```
   Windows'ta interface adı ve monitor mode desteği donanım/sürücüye göre değişir. Birçok Windows adaptörü monitor mode'u desteklemez.

## Kullanım (Linux)
Linux için README ve kullanım daha uygundur. Linux'ta `aircrack-ng` ile arayüzü monitor moda almak genellikle en kolay yöntemdir.

## Lisans ve Etik
Eğitim amaçlıdır. İzinsiz dinleme ve kötü amaçlı kullanım yasaktır. Kullanıcı sorumludur.
