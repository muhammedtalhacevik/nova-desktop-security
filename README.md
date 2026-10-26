# Nova Desktop Security

Windows ve macOS için C# / .NET 10 / Avalonia 11 ile yazılmış masaüstü güvenlik uygulaması.
Tasarım, Nova Mobile Security uygulamasının görsel dilini (lacivert gradyan, yarı saydam kartlar,
renkli ikon kutucukları, Poppins yazı tipi) masaüstü düzenine (sol menü + durum kartı + araç kartları) taşır.

## Özellikler

| Modül | Ne yapar |
|---|---|
| **Virüs taraması** | Hızlı / tam / özel tarama, dosya seçerek veya pencereye sürükle-bırak ile tarama. Duraklat/devam/durdur, ilerleme, HTML rapor. |
| **Tarama motorları** | SHA-256/MD5 imzaları + içerik imzaları, MalwareBazaar (abuse.ch) çevrimiçi imza güncellemesi, sezgisel analiz (çift uzantı, RTLO, sahte belge içindeki program, gizlenmiş PowerShell/bash, fidye yazılımı komutları…), Windows'ta AMSI üzerinden Microsoft Defender motoru. |
| **Gerçek zamanlı koruma** | İndirilenler, Masaüstü, Belgeler, Geçici klasör, Başlangıç / LaunchAgents klasörlerini izler; yeni dosyaları anında tarar, otomatik karantinaya alır. Yeni başlangıç öğelerini de algılar. |
| **Karantina** | Dosyalar şifrelenerek yalıtılır; geri yükleme (izin listesine ekler) veya kalıcı silme. |
| **Web sitesi güvenlik kontrolü** | URL doğrulama, sözcüksel risk sinyalleri (marka taklidi, typosquatting, IP adresi, punycode, riskli uzantı…), yönlendirme zinciri, SSL sertifikası, alan adı yaşı (RDAP), tehdit istihbaratı: OpenPhish (anahtarsız), Google Safe Browsing ve VirusTotal (isteğe bağlı API anahtarıyla). |
| **Ağ güvenliği** | Bağlı ağ (SSID, şifreleme), IP, ağ geçidi, DNS, MAC, genel IP/ISS; risk sinyalleri: şifresiz/zayıf Wi-Fi, ARP sahteciliği, DNS yönlendirme, trafik müdahalesi, güvenlik duvarı, açık servisler, VPN. |
| **Veri ihlali kontrolü** | E-posta adresini XposedOrNot (anahtarsız) veya Have I Been Pwned (API anahtarıyla) üzerinden sorgular; parola sızıntısını k-anonimlik ile kontrol eder (parola cihazdan çıkmaz). |
| **Gizlilik ve başlangıç** | Windows: Run/RunOnce kayıt anahtarları + Başlangıç klasörleri, imza doğrulama, etkinleştir/devre dışı bırak; kamera, mikrofon, konum vb. izinlere erişen uygulamalar ve son kullanım. macOS: LaunchAgents/Daemons, oturum açma öğeleri, TCC izinleri (Tam Disk Erişimi gerekir). |
| **Otomatik tarama** | Günlük/haftalık zamanlanmış tarama (kapalıyken kaçırılan çalıştırılır) ve takılan USB/harici sürücünün otomatik taranması. Windows ve macOS. |
| **Güvenlik denetimi** (yalnızca Windows) | Antivirüs, güvenlik duvarı, SmartScreen, UAC, BitLocker, Windows güncelleme, RDP, Secure Boot kontrolü ve güvenlik puanı. Ayarları kendiliğinden değiştirmez. |
| **Temizleyici** (yalnızca Windows) | Geçici dosyalar, tarayıcı önbellekleri, hata raporları, Windows güncelleme artıkları, geri dönüşüm kutusu. Belgeleri, çerezleri ve parolaları silmez. |
| **Yazılım güncelleyici** (yalnızca Windows) | winget ile eski sürüm uygulamaları bulur ve güncelleyebilir. |
| **Güvenlik merkezi** | Koruma bileşenleri, açık riskler, bildirimler, tarama geçmişi/raporlar, karantina kayıtları. |

> Ağ kontrolleri risk sinyallerini gösterir; yalnızca bu kontrollerle bir Wi-Fi ağının kesinlikle güvenli olduğu söylenemez.

## Proje yapısı

```
src/Nova.Core       Platformdan bağımsız servisler (tarama motoru, karantina, web, ağ, ihlal, gizlilik)
src/Nova.Desktop    Avalonia arayüzü (MVVM, CommunityToolkit.Mvvm, Material ikonları)
tests/Nova.Core.Tests  xUnit testleri (birim + "Live" kategorisinde gerçek servis testleri)
build/              Windows ve macOS yayınlama betikleri
```

Uygulama verileri: Windows `%LOCALAPPDATA%\NovaDesktopSecurity`, macOS `~/Library/Application Support/NovaDesktopSecurity`.

## Geliştirme

Gereksinim: .NET 10 SDK.

```bash
dotnet run --project src/Nova.Desktop                 # uygulamayı çalıştır
dotnet run --project src/Nova.Desktop -- --page=scan  # belirli bir sayfada aç
dotnet test --filter "Category!=Live"                 # birim testleri
dotnet test                                           # gerçek servislerle birlikte tüm testler
```

## Yayınlama

```powershell
.\build\publish-windows.ps1            # publish\win-x64\NovaDesktopSecurity.exe (tek dosya, .NET gerekmez)
```

```bash
./build/publish-macos.sh osx-arm64     # Mac üzerinde: "publish/Nova Desktop Security.app"
```

macOS'ta dağıtım için Developer ID ile imzalama ve notarization gerekir; betik yalnızca yerel ad-hoc imza atar.

## İsteğe bağlı API anahtarları (Ayarlar › Tehdit İstihbaratı Servisleri)

- Google Safe Browsing — https://developers.google.com/safe-browsing/v4/get-started
- VirusTotal — https://www.virustotal.com/gui/my-apikey
- Have I Been Pwned — https://haveibeenpwned.com/API/Key

Anahtarlar yalnızca cihazdaki ayar dosyasında saklanır.

## Platform notları

- **Windows 11 24H2+:** Wi-Fi adı (SSID) için Konum izni gerekir; uygulama izin yoksa bunu belirtir ve ayara yönlendirir.
- **macOS:** Wi-Fi adı için Konum Servisleri, izin raporu için Tam Disk Erişimi, oturum açma öğeleri için Otomasyon izni istenir. AMSI yalnızca Windows'ta vardır.
- Gerçek zamanlı koruma kullanıcı modunda dosya sistemi bildirimleriyle çalışır; çekirdek düzeyinde bir sürücü (dosya açılmadan önce engelleme) içermez.
