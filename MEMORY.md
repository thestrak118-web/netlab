# NetLab — ish holati va davom ettirish (MEMORY)

> Bu fayl keyingi safar **qoldirilgan joydan davom etish** uchun. Oxirgi
> yangilangan: 2026-09-26. Joriy versiya: **2.25.0** (git `a0cfeba`, 422 test
> yashil).

NetLab = Kali uchun Intercepter-NG uslubidagi tarmoq analizatori + MITM vositasi
(PySide6 GUI). Manba: `/home/erwin/loyiha/netlab`. `.deb` fayllar bir pog'ona
yuqorida: `/home/erwin/loyiha/netlab_<versiya>_amd64.deb`.

---

## ⚠️ HAR SAFAR ESLAB QOL — versiya o'zgarmasa

`.deb` o'rnatgach interfeys **o'zgarmasa**, sabab: ishlab turgan NetLab eski
kodni xotirada saqlaydi. Har doim:

```sh
pkill -f /usr/bin/netlab                                   # eskisini o'chir
sudo apt install /home/erwin/loyiha/netlab_2.25.0_amd64.deb
sudo -E netlab                                            # qayta och (-E = X kirish)
```

Sarlavhada versiya ko'rinadi (`NetLab 2.25.0`). Shundan yangi/eski ekanini bил.

---

## Qurish / test / ishga tushirish

```sh
cd /home/erwin/loyiha/netlab
QT_QPA_PLATFORM=offscreen python3 -m pytest tests/ -q     # 422 test
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

## ⏭️ KEYINGI QADAMLAR (davom etish shu yerdan)

Foydalanuvchi umidsizligi: "ko'p mayda o'zgarish, aniq ishlaydigan narsa kerak".
Prioritet tartibda:

1. **[TAKLIF QILINGAN, JAVOB KUTILMOQDA] "Harvest credentials"ni default YOQIQ
   qilish** — user parol sozlamasini izlab yurmasligi uchun. Oson: `config.py`
   DEFAULTS da `harvest_credentials: True`. (Maxfiylik o'zgarishi — README'da
   ayt.)

2. **"Qurilmani kuzat" bir-tugma avto-MITM** — Hostlar'da qurilmani tanlab
   bitta tugma bilan: minimal MITM (ARP + monitor) yoqiladi va o'sha
   qurilmaning Saytlar/Parollari ochiladi. Yangi o'rganuvchi MITM tafsilotini
   bilishi shart emas. (User bir necha marta so'radi.)

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
