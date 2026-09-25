# NetLab — MITM (Interception) bo'yicha amaliy darslik

Bu darslik NetLab'ning **aktiv tomoni** — o'rtada-turish (man-in-the-middle,
MITM) — ni qanday ishlatishni qadamma-qadam ko'rsatadi.

---

## 0. OGOHLANTIRISH — avval o'qing

MITM = ARP-poisoning, SSL-strip, DNS-spoof va boshqalar **haqiqiy hujum
usullari**. Ular:

- **Faqat o'zingiz egalik qiladigan yoki yozma ruxsatingiz bor tarmoqda**
  ishlatilishi mumkin (o'z uy tarmog'ingiz, laboratoriyangiz, ruxsat berilgan
  pentest engagement).
- Begona/ommaviy Wi-Fi'da, ishxona tarmog'ida ruxsatsiz ishlatish —
  **jinoyat**. Bu darslik faqat vakolatli sinov uchun.

NetLab buni "unutib qo'ymaslik" uchun majburlaydi: u siz **scope**'ni
(qaysi manzillarni sinashga haqingiz borligini) e'lon qilmaguningizcha va
tasdiqlamaguningizcha bironta ham soxta kadr yubormaydi.

---

## 1. Nima uchun MITM kerak

Passiv holatda (oddiy sniffing) siz **faqat o'z mashinangiz** traffigini va
broadcast'larni ko'rasiz. Boshqa qurilma (telefon, noutbuk) traffigini ko'rish
uchun uni **o'zingiz orqali o'tkazishingiz** kerak — bu MITM.

MITM yoqilgach:

```
Nishon qurilma  ──►  SIZ (NetLab)  ──►  Gateway  ──►  Internet
   (10.0.0.42)      (soxta ARP bilan)   (10.0.0.1)
```

Nishon qurilma "gateway senmisan?" deб so'raganda NetLab "ha, menman" deydi
(soxta ARP), shuning uchun uning butun traffigi siz orqali o'tadi.

---

## 2. Zarur shartlar

| Nima | Qanday |
|---|---|
| **Root huquqi** | `sudo -E netlab`, yoki menyudan ochsangiz avtomatik root so'raydi |
| **nftables** | `sudo apt install nftables` (redirect qoidalari uchun) |
| **Ikki qurilma** | Sinov uchun: sizning mashinangiz + bitta nishon (telefon/noutbuk), bir xil LAN'da |
| **Bir xil interfeys** | Nishon ham, siz ham bir xil tarmoq (masalan wlan0, 10.0.0.0/24) |

Tekshirish:

```sh
netlab-helper --check      # root, nftables bor-yo'qligini ko'rsatadi
```

---

## 3. Qadamma-qadam engagement

### 3.1. Ishga tushiring va interfeysni tanlang

```sh
sudo -E netlab
```

Yuqori paneldagi **Interface** ro'yxatidan tarmoq kartangizni tanlang
(masalan `wlan0 — 10.0.0.28`). Agar aktiv MITM uchun ishlatsangiz, capture'ni
ham shu interfeysда boshlang (**Start capture**).

### 3.2. Nishonlarni toping (SKANER)

1. **SKANER** rejimi → **Hostlar**.
2. **Discover devices** (yoki yuqoridagi **⌖ Scan**) tugmasini bosing.
   NetLab ARP-sweep qiladi va LAN'dagi qurilmalarni ko'rsatadi.
3. Nishon qurilmani ro'yxatdan toping (IP + MAC + agar bor bo'lsa nomi).

> Eslatma: root'da Scan pkexec so'ramaydi. Nomlar ko'pincha qisman bo'ladi —
> zamonaviy qurilmalar nom e'lon qilmaydi (bu normal).

### 3.3. Nishonni Interception'ga yuboring

- Nishon qatorini tanlab, **Send to Interception** bosing (Ctrl/Shift-click
  bilan bir nechta tanlash mumkin), YOKI
- **MITM** rejimi → **Interception** sahifasini ochib, nishon IP'sini qo'lda
  kiriting.

### 3.4. Engagement'ni sozlang (Interception sahifasi)

1. **Engagement nomi** — masalan `uy-lab-test`.
2. **Scope (nishonlar)** — nishon IP'lari. Formatlar:
   - bitta manzil: `10.0.0.42`
   - diapazon: `10.0.0.40-50`
   - butun tarmoq: `10.0.0.0/24` (butun subnet — ehtiyot bo'ling)
3. **Gateway** — odatda avtomatik aniqlanadi (`10.0.0.1`).

### 3.5. Modullarni tanlang

| Modul | Nima qiladi | Qachon |
|---|---|---|
| **ARP poisoning** | Nishonni siz orqali o'tkazadi (asosiy, doim yoqiq) | Har doim |
| **SSL strip** | `https://` → `http://` ga aylantiradi, parol ochiladi | Web login ushlash uchun |
| **SSL MITM** | TLS'ni o'z CA bilan ochadi (brauzer OGOHLANTIRADI) | Faqat CA o'rnatilgan qurilmada |
| **DNS spoofing** | Tanlangan domenlarga soxta IP qaytaradi | Fishing/redirect testi |
| **Rogue DHCP** | O'zini router qilib ko'rsatadi (eng buzg'unchi) | Ehtiyotkorlik bilan |
| **Traffic changer** | Traffikni jonli almashtiradi (regex) | Kontent o'zgartirish |
| **NTLM relay** | SMB/NTLM autentifikatsiyani relay qiladi | Windows tarmoqlarida |
| **Cookie killer** | Cookie'larni bekor qiladi (qayta login majburlaydi) | Sessiya ushlash |
| **File capture** | O'qiladigan javob tanalarini saqlaydi | Fayl chiqarish |

Yangi boshlovchi uchun tavsiya: **ARP poisoning + SSL strip + File capture**.

### 3.6. Arm (ishga tushirish)

**Arm interception** tugmasini bosing. Dialog ochiladi va u:

- interfeys, gateway, nishonlar va yoqiladigan modullarni ro'yxatlaydi;
- **ruxsat belgisi**ni (checkbox) belgilashni talab qiladi;
- tasdiqlash uchun **`ARM`** so'zini yozishni talab qiladi.

Bu — "adashib bosib qo'ymaslik" himoyasi. Tasdiqlagach, poisoning boshlanadi.

### 3.7. Natijalarni kuzating

| Qayerda | Nima ko'rinadi |
|---|---|
| **KONSOL** | Jonli oqim: poisoning qatorlari, sayt-tashriflar, ushlangan parollar |
| **PAROLLAR** | Ushlangan login/parol/hash'lar (hashcat formatida) |
| **FAYLLAR → Tiklash** | Saqlangan fayllar/javob tanalari |

Nishon qurilmadan bir **HTTP** (shifrsiz) saytga login qiling — parol
KONSOL va PAROLLAR'da chiqishi kerak.

### 3.8. Disarm va tiklash

Ish tugagach **Disarm and restore** bosing. NetLab teskari tartibda tiklaydi:

1. ARP jadvallari (nishonga haqiqiy yo'lni qaytaradi),
2. redirect qoidalari,
3. proxy'lar,
4. paket-uzatish (`ip_forward`).

Dastur qulab tushsa ham (yoki oynani yopsangiz) helper avtomatik tiklaydi —
poisonlangan subnet qolib ketmaydi.

Hamma narsa
`~/.local/share/netlab/engagements/<sana>-<nom>/audit.jsonl` ga yoziladi —
hisobotga ilova qilish mumkin.

---

## 4. HTTPS haqida halol haqiqat

- **SSL strip** — nishon `https://sayt` ga kirmoqchi bo'lsa, NetLab uni
  `http://` ga tushiradi va parol ochiq ko'rinadi. **LEKIN**: qulf (padlock)
  bo'lmaydi, HSTS yoqilgan saytlar (Google, Facebook, banklar) buni
  **bloklaydi**. Ya'ni SSL-strip faqat HSTS'siz eski/oddiy saytlarda ishlaydi.

- **SSL MITM** — TLS'ni NetLab'ning o'z CA'si bilan ochadi. Nishon brauzeri
  **sertifikat ogohlantirishi** beradi — CA o'sha qurilmaga o'rnatilmagan
  bo'lsa. NetLab bu ogohlantirishni yashirmaydi (yashirish mumkin ham emas).
  Test qurilmangizga CA'ni qo'lda o'rnatsangiz — ogohlantirishsiz ishlaydi:
  Interception sahifasidan **CA'ni eksport qiling** → qurilmaga o'rnating →
  engagement tugagach o'chiring.

- **JS-login saytlar** (masalan practicetestautomation.com) — parolni
  brauzer ichida tekshiradi, simga chiqarmaydi. Bularda **hech qanday tool**
  parolni ushlay olmaydi.

**Xulosa:** parolni haqiqatan ushlash uchun eng ishonchli sinov — **shifrsiz
HTTP** sayt (masalan `http://testphp.vulnweb.com/login.php`) yoki test
qurilmangizga NetLab CA'sini o'rnatib SSL-MITM.

---

## 5. Muammolarni bartaraf qilish

**Poisoning yoqildi, lekin nishon traffigi ko'rinmayapti:**

- Nishon va siz **bir xil L2 segmentda**mi (bir xil Wi-Fi/switch)? Boshqa
  VLAN/subnet bo'lsa ARP-poisoning yetib bormaydi.
- Ba'zi Wi-Fi'lar **client isolation** (AP izolyatsiyasi) yoqilgan — bunda
  qurilmalar bir-birini ko'rmaydi, ARP-poisoning imkonsiz. Router sozlamasini
  tekshiring.
- Gateway MAC to'g'ri aniqlanganmi? Interception status'da ko'ring.

**Umuman hech nima o'zgarmayapti:**

- `netlab-helper --check` — root va nftables borligini tasdiqlang.
- `sudo nft list ruleset` — redirect qoidalari o'rnatilganmi.
- `cat /proc/sys/net/ipv4/ip_forward` — `1` bo'lishi kerak (arm paytida).

**To'liq datapath'ni mustaqil sinash** (dasturchi uchun):

```sh
sudo python3 scripts/live_intercept_test.py
```

Bu o'zining ikki-namespace laboratoriyasini quradi va butun yo'lni tekshiradi
(ba'zi kernellarda namespace ichida AF_PACKET ishlamaydi — o'shanda haqiqiy
ikki-mashinali stend kerak; `validation/DATAPATH-VERIFICATION.md`).

---

## 6. Tez xulosa (cheat-sheet)

```
1. sudo -E netlab
2. Interface tanla  →  Start capture
3. SKANER → Discover devices  →  nishonni tanla  →  Send to Interception
4. MITM → Interception:  nom bер, scope (nishon IP), modullar (ARP+SSLstrip)
5. Arm interception  →  ruxsat belgila  →  "ARM" yoz
6. KONSOL / PAROLLAR da kuzat
7. Disarm and restore  (yoki oynani yop — avtomatik tiklaydi)
```

**Doim eslab qol:** faqat o'z tarmog'ingda yoki yozma ruxsat bilan.
