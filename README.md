# Unlocking the Huawei HG531 V1 (ISP‑locked ADSL router) and repurposing it as a WiFi Access Point

A complete, reproducible write‑up of how we took a **carrier‑locked Huawei HG531 V1**
(firmware `V100R001C55B013`, Vodafone Egypt build) — which refused to do anything useful
behind a second router — and turned it into a working **WiFi AP whose clients get their
DHCP lease (and gateway) from the main router**.

Everything here was done on **Linux** (the official Huawei tool is Windows‑only, so we
reverse‑engineered its multicast protocol and re‑implemented the sender in Python).

> ⚠️ Flashing a router is risky. This worked for us, on this exact model/firmware.
> Read everything first, and understand the risk before you start. No warranty.

---

## TL;DR

1. **Problem:** the HG531 V1 is an ADSL router. Behind a cable/fibre main router it acts
   as a dumb AP, but its locked firmware forces its own DHCP (gateway = itself) and it
   won't route its clients — so WiFi clients had **no internet**.
2. **Fix:** flash it with the **unlocked Huawei firmware `V100R001C105B011` (TE‑Data)**
   using Huawei's **Multicast Upgrade Tool (MUT)** protocol — from Linux.
3. **Gotcha:** the main router's **IGMP Snooping** blocks the multicast that MUT uses.
   Turn it **off** (or flood broadcast) or the flash never starts.
4. **After flashing:** you get `admin`/`admin` and a full UI. Enable WiFi, then in
   **LAN settings → DHCP Option Pool** enable **DHCP Relay** for the `Computer` and
   `Phone` pools (and disable the base DHCP option pool). Those clients then get their
   lease from the main router → **gateway 192.168.1.1 + internet**.

---

## 1. The device

| | |
|---|---|
| Model | Huawei **HG531 V1** (EchoLife), 300 Mbps Wireless ADSL2+ Router |
| Board | `AM1HG531V1RMM VER.A` |
| SoC | **Realtek RTL8676S** (Lexra LX5280 @ 450 MHz) |
| Flash / RAM | 4 MiB (Winbond W25Q32) / 32 MiB |
| Ports | 1× DSL, 4× LAN (100 Mbit), WLAN 2.4 GHz |
| Initial firmware | `V100R001C55B013` (Vodafone Egypt build) |
| Unlocked firmware | `V100R001C105B011` (TE‑Data / WE, Egypt) |

There is **no OpenWrt / DD‑WRT / Tomato** for this chipset — only Huawei vendor firmware.

**Goal:** use it as a WiFi AP behind a main router (a TP‑Link at `192.168.1.1`, in our case),
with clients automatically getting the main router's DHCP (gateway `192.168.1.1`).

---

## 2. Why the locked web UI is a dead end

The stock Vodafone build only gives you a crippled `vodafone`/`vodafone` **user** account
(no admin). We mapped the entire user‑reachable surface and it simply **cannot** do what we
need:

* The DHCP gateway / option‑3 **does not exist** in any user‑reachable object. The device
  always advertises *its own* LAN IP as the gateway, and there is no field to change it.
* The `setcfg.cgi` / `addcfg.cgi` whitelist for a user rejects any object outside the
  user pages (routes, TR‑069 `ManagementServer`, conditional pools, …) with a generic
  `ErrInfo = 1074266212`.
* **Firmware upgrade is disabled**: `/lang/firmware.res` contains
  `"Upgrade fail. You can only upgrade by TR069."`, the firmware page is admin‑only
  (deep‑linking it force‑logs‑out the user), and the upload endpoint returns `888`
  (unauthorized).
* The configuration backup (`downloadconfigfile.conf`) is **encrypted** with an
  unknown, per‑device scheme — no key material recoverable from the image.
* The classic Huawei UPnP RCE (`:37215` `/ctrlt/DeviceUpgrade_1`) is **patched** on this
  build (returns `402`), and the diagnose ping CGI validates its input.
* The default account list (`admin/admin`, `vodafone/vodafone`, …) gave only the user login.

So the **only** way in was to replace the firmware. That's where MUT comes in.

---

## 3. The unlock: Huawei Multicast Upgrade Tool (MUT)

Huawei DSL/LTE CPEs and routers can be reflashed **over the LAN during boot** by a tool
that broadcasts the firmware image as **UDP multicast**. This bypasses the web UI,
the admin login and the "TR069‑only" lock entirely.

* Tool (Windows): `Upgrade Tool_Multicast Package Transmit Tool_MUT_eng` → `MUT_eng.exe`
  (also mirrored as `HuaweiMUT.exe`). We used it only as a protocol reference; the
  community Python re‑implementation
  ([Rezurmas/huawei-mut-unbrick-tool](https://github.com/Rezurmas/huawei-mut-unbrick-tool))
  documents the protocol byte‑by‑byte.
* Firmware: `HG531V1V100R001C105B011_multicast_packet.bin` (+ its `.ini`), from the
  Egyptian community (see Credits). The image is flashed to the `kernelfs` partition
  **only** — the bootloader (`CFE`) is deliberately left untouched, so a bad flash is
  recoverable by re‑flashing.

### 3.1 The MUT protocol (short version)

| | |
|---|---|
| Transport | UDP multicast, **`224.0.0.119:13456`** (source port also 13456) |
| Packet | **1086 bytes** = 62‑byte header + 1024‑byte data chunk |
| `control_word` | `(opcode << 29) | 0x00000400` — `INIT=0x80000400`, `DATA=0x20000400`, `LAST=0x40000400` |
| Header | `control_word, seq, chunk_crc32, total_size, fw_crc32, PACKAGE_ID[20], word, PRODUCT_ID[20]` |
| INIT payload | the partition table (32 bytes/entry: name[20], start, end, cover‑flag) |
| `PACKAGE_ID`/`PRODUCT_ID` | `fnt-HGW` for this model |
| Partitions | `CFE,0x0-0xFFFF,uncover | kernelfs,0x10000-0x3FFFFF,cover` |
| Loop | send INIT, then DATA×N (last one is LAST, zero‑padded), repeat |

The router's bootloader listens for this on its LAN ports for a short window after
power‑on, buffers the whole image in RAM, verifies the CRC, then writes the `kernelfs`
partition and reboots.

Full details in [`docs/mut-protocol.md`](docs/mut-protocol.md).

### 3.2 The one thing that stops it working: **IGMP Snooping**

If a managed switch or router sits between your PC and the HG531 (as our TP‑Link did),
its **IGMP Snooping** will *not* flood the `224.0.0.119` multicast to the port the router
is on → the bootloader never sees the image → it just boots normally.

**Fix:** turn **IGMP Snooping OFF** on the main router (TP‑Link: *Advanced → Network →
IPTV*), or connect your PC **directly** to the HG531's LAN port (bypassing the router).
The community documentation even says *"set the switch in multicast mode"* for exactly
this reason.

---

## 4. Flashing (from Linux)

We re‑implemented the MUT sender in Python: **[`tools/mut_flash.py`](tools/mut_flash.py)**.

**Requirements & setup**

* The **unlocked firmware** `…_multicast_packet.bin` + its matching `.ini` (the `.ini`
  supplies `PACKAGE_ID`, `PRODUCT_ID`, `PARTITIONS`, sizes, CRCs — the repo's files are
  self‑consistent — verified).
* Your PC on the **same L2 segment** as the HG531's LAN port.
* **IGMP Snooping disabled** on any intermediate switch/router.

**Procedure**

```bash
# 1. Start the sender (loops the image forever; harmless until the router is in its bootloader)
python3 tools/mut_flash.py \
  --bin HG531V1V100R001C105B011_multicast_packet.bin \
  --ini HG531V1V100R001C105B011_multicast_packet.ini \
  --iface-ip 192.168.1.104 \
  --interval-ms 20 --dest both
#   --dest both   sends to the multicast group AND 255.255.255.255 (helps bypass snooping)
#   --interval-ms 20   matches the original tool's conf.dat (50 pkt/s); ~71s per pass

# 2. Power-cycle the HG531: OFF, wait ~10s, ON.
#    Watch the LAN LED — a rapid blink means it is downloading.
#    (Power LED slow blink = writing flash; DO NOT cut power then.)
```

Notes that saved us:

* Keep the image name matching so the `.ini` is found (use `--bin`/`--ini`).
* `--dest both` (multicast + broadcast) was what finally got packets to the bootloader
  through a snooping router; once snooping is disabled, plain multicast works too.
* The last successful sequence was: **stop the loop, then power-cycle** for a clean,
  uninterrupted download — the bootloader needs the whole image in one go.
* The sender is safe to leave running: the bootloader only listens for a few seconds at
  boot, so a running loop causes no harm to a normally‑booting router.

After a successful write the router boots the **unlocked firmware**. You can confirm it:

```
Maintenance/Status → Device information
  Software: V100R001C105B011 TEDATA
Login: admin / admin        (fallback: admin / @A5d6m7i8n)
```

### Flashing on Windows (original tool)

If you'd rather use Huawei's own tool: extract
`Upgrade Tool_Multicast Package Transmit Tool_MUT_eng` (contains `MUT_eng.exe` +
`conf.dat` + a `.doc`), run `MUT_eng.exe` as Administrator, pick your NIC, `refresh`,
`open` the firmware `.bin`, `start`, then **power‑cycle the HG531**. Same prerequisites.

---

## 5. Post‑flash: making it a real AP with gateway `.1`

Once unlocked, log in as `admin` and configure:

1. **LAN** → set the HG531's LAN IP to a free address in the main subnet
   (e.g. `192.168.1.200`), so it doesn't clash with the main router.
2. **WLAN** → enable the radio, set your SSID + **WPA2** password.
3. **LAN → DHCP Option Pool**:
   * enable **DHCP Relay** for the **`Computer`** and **`Phone`** pools, and
   * **disable the base DHCP Option Pool**.

With relay enabled for those device classes, the HG531 **forwards those clients' DHCP
requests to your main router**, which answers with its own lease — so the client's
**gateway becomes `192.168.1.1`** and it has internet through the main router. This is the
key step: merely *disabling* the HG531's DHCP (without the relay pools) leaves clients
with no IP, because the firmware intercepts external DHCP for un‑relayed clients.

**Result:** connect a phone/computer to the HG531's WiFi → it gets an IP + gateway
`192.168.1.1` from the main router → full internet. ✅

---

## 6. Repo contents

```
.
├── README.md                 # this file
├── docs/
│   └── mut-protocol.md       # MUT packet format, byte-by-byte
└── tools/
    ├── mut_flash.py          # Linux MUT sender (the flasher)
    └── mut_monitor.py        # tiny ping monitor used to watch the reboot
```

The **firmware** is not bundled (it's Huawei's, and large) — grab the matching
`…_C105B011_multicast_packet.bin` + `.ini` from the community links below.

---

## 7. Credits & links

* **egpr.net** — the Egyptian guides that document the HG531 V1 unlock/flash
  (*"فك تشفير راوتر اتصالات huawei hg531 v1"*) and the WE/TE‑Data firmware.
* **HG531‑Fix** GitHub repos (`Aboalfadl/HG531-Fix`, `DarkWarrior0x/HG531-Fix`) — the
  TE‑Data unlock write‑up + firmware mirror.
* **Rezurmas/huawei-mut-unbrick-tool** — open‑source Python re‑implementation of Huawei's
  MUT (our protocol reference).
* **blog.hqcodeshop.fi** (Jari Turkia) — the original E5186 MUT recovery write‑up.
* **HalabTech** — HG531 firmware archive.
* Huawei HG531 V1 manual/datasheet — bridge‑mode and LED behaviour.

## 8. Disclaimer

This is a community how‑to for **your own** hardware. Flashing firmware can brick your
device, void warranties, and may conflict with your ISP's terms. Use at your own risk.
All trademarks belong to their owners.
