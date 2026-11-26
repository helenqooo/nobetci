# Nöbetçi

**Behaviour-based protection for Windows**, running next to Microsoft Defender. Nöbetçi uses ETW (kernel process,
file and Win32k audit events) to watch for persistence, security-tool tampering, keyloggers and clipboard hijackers,
ransomware-style mass file changes and vulnerable-driver (BYOVD) drops. It also has a static PE/script scanner with
AMSI integration, user rules and a quarantine. When something suspicious happens it tells you which process did it and
can stop it. No kernel driver: it reacts after a process starts, it cannot block it beforehand.

Build: .NET 8 SDK, Windows x64 — `dotnet build -c Release`. Run as administrator. Licensed under [AGPL-3.0](LICENSE).
Security reports: see [SECURITY.md](SECURITY.md).

*The full documentation below is in Turkish.*

---

# Nöbetçi

Windows için davranış tabanlı koruma. Bilgisayarda nöbet tutar: yeni başlayan işlemlere, otomatik başlayan her şeye, hosts dosyasına, güvenlik duvarına ve Defender ayarlarına, klavyeyi ve panoyu dinleyenlere, belgeleri toplu halde değiştirenlere ve diske bırakılan dosyalara bakar; şüpheli bir şey olursa kim yaptığını söyler, istersen durdurur.

Bu bir sürücü (kernel) bileşeni içermez. Yani bir işlem başladıktan sonra yakalar ve durdurur; başlamadan önce engelleyemez. Defender'ın yerine değil, yanına kurulur.

## Ne izliyor

| Katman | Nasıl | Ne yakalar |
|---|---|---|
| **İşlem izleme** | ETW çekirdek olayları (komut satırı dahil) | Güvenlik duvarını/Defender'ı kapatan komutlar, hosts'a yazan komutlar, sürücü servisi kuran komutlar, yedek silme, günlük silme, şifreli PowerShell, indirip çalıştıran sistem araçları, Office'ten komut yorumlayıcı başlatma, kullanıcı klasöründen çalışan imzasız programlar |
| **Otomatik başlatma** | Her 3 sn anlık görüntü karşılaştırması + ETW'den "kim yazdı" | Run/RunOnce, servisler ve sürücüler, zamanlanmış görevler, başlangıç klasörleri, IFEO, Winlogon, AppInit, WMI kalıcılığı |
| **Sistem bekçisi** | Durum izleme | hosts değişikliği (geri alma dahil), güvenlik duvarı kapatma, Defender koruması ve dışlamaları |
| **Dosya olayları** | ETW | hosts'a yazma, başlangıç klasörüne dosya bırakma, `.sys` sürücü dosyası bırakma |
| **Casus koruması** | ETW pencere yöneticisi (Win32k) denetim olayları | Sistem genelinde klavye kancası (`WH_KEYBOARD_LL`, `WH_KEYBOARD`), arka planda ham klavye girdisi (`RIDEV_INPUTSINK`), arka planda tuş yoklama (`GetAsyncKeyState`), başkasının panosunu tekrar tekrar okuma, okuyup hemen değiştirme (kripto adresi değiştiriciler) |
| **Fidye yazılımı koruması** | ETW dosya olayları + tuzak dosyalar | 15 sn içinde 20+ belgeyi yeniden adlandırma, 40+ belge silme, belgeleri rastgele veriyle yeniden yazma (içerik örneklenip entropi ve dosya başlığına bakılır), tuzak dosyaya dokunma |
| **Dosya tarama** | Statik PE/betik analizi + AMSI + listeler | Paketleyici bölümleri, şifrelenmiş kod, enjeksiyon/boşaltma (hollowing) API'leri, tarayıcı parolası ve cüzdan hırsızlığı dizgileri, Telegram/Discord'a veri kaçırma, çift uzantı, Temp'te sistem dosyası adı, zararlı betik satırları, zafiyetli sürücüler (BYOVD), Defender'ın tanıdığı her şey |

Güvenilir programlar (Windows klasöründekiler, geçerli imzalılar, izin verdiklerin) casus ve fidye uyarılarında sessiz geçilir; betik yorumlayıcıları (powershell, wscript, python…) imzalı olsalar da güvenilir sayılmaz.

### Dosya tarama ayrıntısı

- **Ne zaman:** kullanıcı klasörlerine (Temp, AppData, İndirilenler, Masaüstü, ProgramData…) ya da `drivers` klasörüne çalıştırılabilir dosya/betik yazıldığında; Windows dışından bir program başladığında; elle (tepsi menüsü → *Dosya tara… / Klasör tara…* ya da `--scan`).
- **Puan:** 0–100. 40 ve üstü *şüpheli*, 70 ve üstü *zararlı*. Geçerli imzalı dosyaların puanı 0,3 ile, yalnız yöneticinin yazabildiği klasörlerde (Windows, Program Files) kurulu imzasız dosyalarınki 0,6 ile çarpılır.
- **İmza:** dosyanın içindeki Authenticode imzası ya da Windows güvenlik kataloğu (cmd.exe gibi Windows dosyaları böyle imzalıdır); katalogun kendi imzası da doğrulanır.
- **Ad hileleri imzaya bakmaz:** çift uzantı (`fatura.pdf.exe`), Windows dışında duran `svchost.exe` gibi sistem adları ve Windows araçlarının (cmd, powershell, mshta, rundll32…) başka klasöre kopyalanmış / yeniden adlandırılmış hâlleri tam puanla işaretlenir. Yeniden adlandırılmış bir yorumlayıcı casus ve fidye korumasında da güvenilir sayılmaz.
- **Klasör taraması** birkaç iş parçacığıyla çalışır (bir çekirdek boşta bırakılır); rapor sonunda sürenin nereye gittiği yazar.
- **Kesin isabet** (puan 100): `block.txt`'deki SHA-256, loldrivers.io listesindeki sürücü özeti ya da bilinen zafiyetli sürücü adı, AMSI'nin (Defender ya da kurulu antivirüs) "zararlı" demesi. *Durdur ve sor* modunda kesin isabetler kendiliğinden karantinaya alınır; diğerleri için uyarıda *Karantinaya al / Güvenilir yap* düğmeleri çıkar.
- **Karantina:** dosya `quarantine\<sha>.q` olarak baytları çevrilmiş halde saklanır (çalıştırılamaz), yanında nereden geldiğini yazan `.txt` durur; *Geri yükle* eski yerine koyar.
- **Kendi kuralların:** `rules.txt`, satır başına bir kural: `ad|puan|all|kelime1,kelime2` (hepsi geçmeli) ya da `ad|puan|any:2|k1,k2,k3` (en az 2'si). Küçük/büyük harf ayrımı yok, `#` yorum.
- **Kara liste:** `block.txt`, satır başına bir SHA-256 (ardından isteğe bağlı not).
- **Sürücü listesi:** `loldrivers.txt` haftada bir loldrivers.io'dan yenilenir (şu an ~4100 özet); internet yoksa gömülü ad listesi çalışır. Windows'un kendi sürücü deposunda (`System32\DriverStore`) duran ve Windows kataloğunda kayıtlı listelenmiş sürücü *şüpheli* diye bildirilir ama kesin isabet sayılmaz, karantinaya alınmaz; aynı dosya başka bir yere bırakılırsa kesin isabettir.

Her uyarıda ne olduğu, hangi program olduğu (yol, PID, üst işlem, yayıncı, komut satırı) ve düğmeler var: Engelle / İzin ver / Kaldır / Geri al / Kabul et.

## Modlar

- **Yalnız izle** (varsayılan): uyarı verir, hiçbir şeyi durdurmaz.
- **Durdur ve sor**: tehlikeli bir işlem başlayınca hemen askıya alır, karar sorar. İzin verirsen dosyanın SHA-256'sı güvenilir listeye girer.
- **`--dry`**: kuru çalışma. Hiçbir durumda durdurma/silme/geri alma yapmaz. Sunucuda ve testte kullan.

## Çalıştırma ve test

```
dist\Nobetci.exe              # tepsi simgesi + pencere (yönetici izni ister)
dist\Nobetci.exe --hidden     # yalnız tepsi
dist\Nobetci.exe --dry        # hiçbir şeye müdahale etmez
dist\Nobetci.exe --scan <dosya|klasör>   # tara, raporu yaz, çık (çıkış kodu: 0 temiz, 1 şüpheli, 2 zararlı)
dist\Nobetci.exe --selftest   # 106 otomatik test, sonucu selftest.txt'ye yazar
```

Öz-test kendi geçici klasöründe çalışır: sahte PE dosyaları üretir, kendi sahte belgelerini "şifreler" ve yeniden adlandırır, bir an için klavye kancası kurup kaldırır, tuzak dosyayı başka bir işleme sildirir ve her birinin canlı olarak yakalandığını doğrular. Çalışabilir hiçbir zararlı içermez; AMSI denemesindeki standart test dizgisi yalnız bellekte kurulur, diske yazılmaz.

Veriler `C:\ProgramData\Nobetci` altında: `events.log`, `allow.txt`, `block.txt`, `rules.txt`, `loldrivers.txt`, `config.ini`, `autorun.base`, `hosts.base`, `scan-report.txt`, `quarantine\`.

`config.ini` ayarları: `mode=monitor|ask`, `strict=1` (kullanıcı klasöründen başlayan imzasız programları bildir), `canary=1` (Belgeler, Masaüstü ve Resimler'e gizli `!0_nobetci_tuzak_dosya_silme.docx` tuzak dosyası koy; `0` yaparsan konmaz).

## Derleme

Projenin içindeki taşınabilir .NET 8 SDK kullanılır (`.dotnet\`), sisteme bir şey kurulmaz.

```
set DOTNET_ROOT=%CD%\.dotnet
.dotnet\dotnet.exe build Nobetci.csproj -c Release -o bin
.dotnet\dotnet.exe publish Nobetci.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o dist
```

Tek dosya (`PublishSingleFile=true`) yapma: TraceEvent'in yerel kütüphaneleri (`amd64\KernelTraceControl.dll`) exe'nin yanında durmak zorunda.

## Bilinen sınırlar

- Sürücü yok: bir program başlamadan engellenemez; her şey olaydan sonra (ETW olayları ~1 sn gecikmeli gelir) yakalanır ve durdurulur. Fidye yazılımı durdurulana kadar birkaç dosya şifrelenmiş olabilir.
- Ekran görüntüsü alma anı görülemiyor (Windows bunun için olay üretmiyor); yalnızca dosya taramasında "ekran görüntüsü alabilir" diye düşük puanla işaretleniyor.
- Tuş kaydedici kancası kurulduğu anda görülür, tuşları okuduğu görülmez. Kendi sürücüsünü yükleyen ya da doğrudan sistem çağrısı yapan kaydediciler bu olayları üretmeyebilir.
- Dosya tarama statik ve sezgiseldir: imza veritabanı yok (yalnız AMSI üzerinden Defender'ınki), YARA yok, bulut özet sorgusu yok. Özel paketlenmiş yeni bir zararlı düşük puan alabilir; puan bir kanıt değil, bakılacak yer işaretidir.
- İmzasız exe: SmartScreen ve bazı antivirüsler uyarır; dağıtmadan önce kod imzalama gerekir.
- ETW çekirdek oturumu tek: aynı anda başka bir "NT Kernel Logger" kullanan araç (ör. bazı profilleyiciler) varsa Nöbetçi onu durdurur.
- Kayıt defteri olaylarında çekirdek anahtar yolunu vermiyor; kim yazdığı değer adı üzerinden eşleştiriliyor.
