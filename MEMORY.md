# NetLab — ish holati va davom ettirish (MEMORY)

> Bu fayl keyingi safar **qoldirilgan joydan davom etish** uchun. Oxirgi
> yangilangan: 2026-09-28. Joriy manba versiyasi: **2.37.1**.
> Lifecycle/recovery tuzatishlari ishchi daraxtda; yangi .deb hali qurilmagan.
> Tekshiruv: 484/484 test o'tdi (34.92 s); 14 yangi regressiya testi.

NetLab = Kali uchun Intercepter-NG uslubidagi tarmoq analizatori + MITM vositasi
(PySide6 GUI). Manba: `/home/erwin/loyiha/netlab`. `.deb` fayllar bir pog'ona
yuqorida: `/home/erwin/loyiha/netlab_<versiya>_amd64.deb`.

---

## ⚠️ HAR SAFAR ESLAB QOL — versiya o'zgarmasa

`.deb` o'rnatgach interfeys **o'zgarmasa**, sabab: ishlab turgan NetLab eski
kodni xotirada saqlaydi. Har doim:

```sh
pkill -f /usr/bin/netlab                                   # eskisini o'chir
sudo apt install /home/erwin/loyiha/netlab_2.37.1_amd64.deb
sudo -E netlab                                            # qayta och (-E = X kirish)
```

Sarlavhada versiya ko'rinadi (`NetLab 2.37.1`). Shundan yangi/eski ekanini bил.

---

## Qurish / test / ishga tushirish

```sh
cd /home/erwin/loyiha/netlab
QT_QPA_PLATFORM=offscreen python3 -m pytest tests/ -q
dpkg-buildpackage -us -uc -b                              # .deb qurish -> ../
sudo -E netlab                                            # root bilan ochish
sudo -E netlab --check                                    # capture/root holati
```

Versiya oshirish: `src/netlab/__init__.py` + `pyproject.toml` + `debian/changelog`
+ README dagi install qatoridagi versiya, keyin build. Sudo paroli: `kali`.

---

## ✅ ISHLAYDI (isbotlangan)

- **Passiv tahlil** — dumpcap capture, HTTP/DNS/TLS/reassembly o'zi dekodlaydi.
- **Shifrsiz parol ushlash** — JONLI ISBOTLANDI (2026-09-26): loopback'da HTTP
  form POST → NetLab `erwin / SuperSecret123!` ni to'liq ajratdi. Ikki shart:
  (1) sayt **HTTP** (HTTPS emas), (2) SOZLAMALAR → **"Harvest credentials"**
  YOQIQ (default O'CHIQ, maxfiylik uchun).
- **Konsol (KONSOL)** — jonli sayt-tashriflarni ko'rsatadi (TLS SNI + HTTP host,
  deduped) + passiv parollar.
- **Root bilan ishlash** — `sudo -E netlab` yoki menyudan avto-root (pkexec);
  config/fayllar operator uyida qoladi (`real_user()` SUDO_UID orqali).
- **Native nom aniqlash** — reverse-DNS/NBNS/UPnP/mDNS, nmap/root'siz.
- **QUIC/HTTP-3 SNI (2.27.0)** — Instagram/YouTube/Google endi nomini ko'rsatadi (QUIC Initial deshifrlash, RFC 9001, paketlararo ClientHello). Jonli isbotlangan.
- **"Kuzat" bir-tugma oqim (2.26.0)** — qurilma tanla → saytlar+parol. O'z
  qurilma passiv ISHLAYDI; boshqa qurilma MITM datapath'iga bog'liq (isbotlanmagan).

## ❌ ISHLAMAYDI / ISBOTLANMAGAN (halol)

- **HTTPS parol passiv ko'rinmaydi** — shifrlangan (fizika). JS-login saytlar
  (masalan practicetestautomation.com) parolni simga umuman chiqarmaydi.
- **Aktiv MITM datapath (ARP→redirect→proxy) real temirda ISBOTLANMAGAN** —
  loopback unit-testlar o'tadi, lekin bu muhit netns/AF_PACKET sababli to'liq
  yo'lni yurita olmaydi. `validation/DATAPATH-VERIFICATION.md`. **Eng katta
  ochiq savol.**
- **Nom aniqlash ko'pincha qisman** — zamonaviy qurilmalar nom e'lon qilmaydi
  (user LAN'ida faqat gateway javob berdi). Bu real shift, bug emas.

---

## Bu sessiyada qilingan ish (2.16 → 2.25)

| Ver | Ish |
|---|---|
| 2.16 | git repo boshlandi + CI |
| 2.17 | host-markazli 3-rejim GUI (keyin 2.22 da 5 rejimga) |
| 2.18 | tashqi auditning 6 topilmasi + kesilgan-pcap ogohlantirishi |
| 2.19-2.20 | native nom aniqlash (rDNS/NBNS/UPnP/mDNS) + root bilan ishlash |
| 2.21 | menyudan avto-root (pkexec launcher) |
| 2.22 | IntNG-uslub 5 ikonali rejim (SKANER·TRAFFIK·PAROLLAR·KONSOL·MITM) + yashil "Packets:" |
| 2.23 | konsol jonli sayt-tashriflarni ko'rsatadi |
| 2.24 | Interception sahifasi soddalashtirildi ("Ilg'or" toggle) |
| 2.25 | toolbar'dan BPF yashirildi + Hostlar 9→5 ustun |
| — | `docs/MITM-DARSLIK.md` — MITM darsligi (o'zbekcha) |

---

## 2026-09-28: lifecycle va recovery tuzatishlari

- Helper arm/disarm/shutdown ketma-ket bajariladi; shutdown’dan keyingi start rad etiladi.
- Sysctl yozuvi tekshiriladi; tiklanmagan qiymatlar qayta urinish uchun saqlanadi.
- Wi-Fi qisman startdan keyin ham tiklanadi; tiklash xatolari yashirilmaydi.
- GUI recovery tugamasa yangi Kuzat’ni boshlamaydi, Disarm tugmasi faol qoladi.
- Metadata/README/CLI yordam matni amaldagi xulqqa moslandi.
- Real ARP datapath bu tuzatish paytida sinalmadi.

## ⏭️ KEYINGI QADAMLAR (davom etish shu yerdan)

Foydalanuvchi umidsizligi: "ko'p mayda o'zgarish, aniq ishlaydigan narsa kerak".
Prioritet tartibda:

1. **[✅ HAL QILINDI] Parol yig'ish** — "Kuzat" tugmasi harvest'ni majburan
   yoqadi (_apply_harvest). Config default OFF qoldi (maxfiylik + testlar). Agar
   user Kuzat'siz ham parol istasa, SOZLAMALAR → Harvest credentials.

2. **[✅ BAJARILDI 2.26.0] "Kuzat (saytlar + parol)" tugmasi** — Hostlar'da
   qurilma tanlab bir tugma: o'z qurilma passiv ochiladi; boshqa qurilma uchun
   minimal MITM (ARP+SSL-strip+carve) yoqiladi + arm dialog + Selected Device
   ko'rinishi (Saytlar/Parollar). Harvest majburan yoqiladi. LEKIN boshqa
   qurilma uchun REAL datapath (keyingi #3) hali isbotlanmagan.

3. **REAL MITM sinovi** — o'z LAN'ida ikki qurilma bilan, `sudo` ostida
   datapath'ni haqiqatan tekshirish. Bu — flagman ishlashini bilishning YAGONA
   yo'li. HTTP sayt + nishon qurilma bilan `erwin/SuperSecret` kabi parol
   chiqadimi ko'rish.

4. **Interfeys soddalashuvi davom** (agar user hali "chalkash" desa) — qaysi
   sahifa aniq bo'lsa, o'sha. Boshqa dense joylar: DNS/HTTP/TLS sahifalari
   ustunlari, "View Traffic/…/PCAP" 6-tugma qatori.

5. **MITM-DARSLIK.md ni PDF qilish** (user report-template uslubini yaxshi
   ko'radi — `/home/erwin/offsec-report-template`).

---

## Foydali fayllar

- `docs/MITM-DARSLIK.md` — MITM ishlatish darsligi
- `validation/DATAPATH-VERIFICATION.md` — datapath sinov holati
- `scripts/live_intercept_test.py` — end-to-end MITM sinovi (real sudo kerak)
- `src/netlab/analyze/creds.py` + `credfmt.py` — parol ajratish (30+ protokol)
- `src/netlab/intercept/` — aktiv modullar (arp/proxy/dns/dhcp/ntlm_relay)
- `src/netlab/gui/main_window.py` — asosiy oyna, nav, toolbar, _tick
- `src/netlab/gui/pages/mitmpage.py` — Interception sahifasi
- `src/netlab/gui/pages/console.py` — KONSOL

## Halol umumiy baho

Passiv analizator: **mustahkam, sinalgan** (8/10). Aktiv MITM kodi:
**yaxshi yozilgan** (7/10), lekin **real temirda ishlashi isbotlanmagan**
(?/10). IntNG o'rnini to'liq bosishi uchun — aktiv datapath real sinovdan
o'tishi kerak (keyingi qadam #3).
