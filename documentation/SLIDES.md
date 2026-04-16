---
marp: true
theme: default
paginate: true
style: |
  section {
    font-family: 'Segoe UI', sans-serif;
    font-size: 22px;
  }
  h1 { color: #1a3c6e; font-size: 40px; }
  h2 { color: #1a3c6e; font-size: 30px; border-bottom: 2px solid #1a3c6e; padding-bottom: 6px; }
  h3 { color: #2563a8; font-size: 24px; }
  code { background: #f0f4ff; border-radius: 4px; padding: 2px 6px; }
  pre { background: #1e1e2e; color: #cdd6f4; border-radius: 8px; padding: 16px; }
  table { width: 100%; border-collapse: collapse; }
  th { background: #1a3c6e; color: white; padding: 8px; }
  td { padding: 8px; border-bottom: 1px solid #ddd; }
  .tag { display: inline-block; background: #e8f0fe; color: #1a3c6e; border-radius: 4px; padding: 2px 8px; font-size: 16px; font-weight: bold; margin: 2px; }
  .green { color: #16a34a; font-weight: bold; }
  .red { color: #dc2626; font-weight: bold; }
  .orange { color: #ea580c; font-weight: bold; }
---

<!-- Slide 1: Title -->
# CS441 — Network Security Project
## IP-over-Ethernet Network Emulator

**Team:** Group 1, Team 3
**Demo Duration:** 20 min + 10 min Q&A

---

<!-- Slide 2: What We Built -->
## What We Built

A **software-emulated IP-over-Ethernet network** — every device runs as a separate Java process communicating over localhost UDP.

```
        ┌──────────────────────────────┐
        │           ROUTER             │
        │   R1 (0x11) R2 (0x21) R3 (0x31) │
        └────┬──────────┬──────────┬───┘
             │          │          │
          LAN1        LAN2        LAN3
        ┌────┴────┐  ┌──┴──┐   ┌──┴──┐
        N1       N2 N3         N4
      0x12     0x13 0x22      0x32
     ATTACKER NORMAL FIREWALL NORMAL
```

**8 separate processes** — 3 LAN emulators + 1 Router + 4 Nodes

---

<!-- Slide 4: Protocol Stack -->
## Protocol Stack

**Ethernet Frame**
```
[ Src MAC (2B) | Dst MAC (2B) | Length (1B) | Data (up to 256B) ]
  e.g.  N1          R1            7             IP packet
```

**IP Packet** _(inside Ethernet data)_
```
[ Src IP (1B) | Dst IP (1B) | Protocol (1B) | Length (1B) | Data ]
  e.g. 0x12      0x22           0x01 (ICMP)      10          Ping
```

**Addressing rule:** High nibble of IP = LAN ID
- `0x1_` → LAN1 &nbsp;&nbsp; `0x2_` → LAN2 &nbsp;&nbsp; `0x3_` → LAN3

---

<!-- Slide 5: Demo Overview -->
## Demo Plan

| # | Feature | Time | Rubric |
|---|---------|------|--------|
| 1 | DHCP dynamic IP assignment | 2 min | Open |
| 2 | Ethernet broadcast + MAC filter | 1.5 min | 2% |
| 3 | IP routing across LANs | 2 min | 3%+2% |
| 4 | Ping with RTT | 0.5 min | 1% |
| 5 | IP Spoofing attack | 2 min | 2% |
| 6 | Sniffing attack | 1.5 min | 1% |
| 7 | Firewall (add/remove rules) | 2 min | 2% |
| 8 | Encrypted messaging vs sniffing | 1.5 min | Open |
| 9 | IDS — spoof detection | 1.5 min | Open |
| 10 | IDS — ping flood detection | 1.5 min | Open |
| 11 | ARP Spoofing + DAI | 1.5 min | Open |

---

<!-- Slide 6: Demo 1 — DHCP -->
## Demo 1 — DHCP Dynamic IP Assignment
### Open Category

**What happens at startup:**

```
Node1  →  DISCOVER (broadcast, src=0x00)
Router →  OFFER    (0x12 available)
Node1  →  REQUEST  (I want 0x12)
Router →  ACK      (0x12 leased to N1 for 60s)
```

**Router log shows:**
```
DHCP[LAN1]: ACK — leased 0x12 to N1 for 60s
IDS snoop:  learned N1 -> 0x12   ← fed into IDS immediately
```

> Nodes have **no hardcoded IPs** — all addresses are dynamically assigned.
> The IDS learns MAC↔IP bindings from each lease automatically.

---

<!-- Slide 7: Demo 2+3 — Ethernet & IP -->
## Demo 2 & 3 — Ethernet Broadcast + IP Routing

**Demo 2 — Same LAN (Node2 pings Node1)**

- LAN1 broadcasts frame to all devices
- Router R1 receives it → **drops** (dst MAC = `N1`, not `R1`)
- Node1 receives it → **accepts** → replies

**Demo 3 — Cross LAN (Node1 pings Node4)**

```
Node1 (LAN1)  →  Router R1  →  [routing decision]  →  Router R3  →  Node4 (LAN3)
   N1→R1                        dst=0x32 → LAN3              R3→N4
```

- New Ethernet frame on each LAN segment (MACs change, IP unchanged)
- Proves IP and Ethernet are separate layers

---

<!-- Slide 8: Demo 5 — IP Spoofing -->
## Demo 5 — IP Spoofing Attack
### Rubric: 2%

**Scenario:** Node1 impersonates Node2 to send packets to Node3

```
Node1 CLI:   spoof on 0x13
             ping 0x22
```

**What Node3 sees:**
```
RX Packet [0x13 -> 0x22 | ICMP]   ← believes it came from Node2
```

**What actually happened:**
```
Real sender:  Node1 (MAC=N1, real IP=0x12)
Forged field: Source IP = 0x13  (Node2's address)
```

> IP has **no source authentication** — any node can put any IP in the source field.

---

<!-- Slide 9: Demo 6 — Sniffing -->
## Demo 6 — Sniffing Attack
### Rubric: 1%

**Scenario:** Node1 eavesdrops on Node2's private message to Node3

```
Node1 CLI:   sniff on
Node2 CLI:   msg 0x22  Hello from Node2
```

**Node1 intercepts:**
```
[SNIFF] Frame [N2 -> R1 | 22 bytes]
        Packet [0x13 -> 0x22 | DATA]
        Text: "Hello from Node2"    ← private message exposed
```

**How it works:**
- Normal mode: drop any frame where dst MAC ≠ `N1`
- Promiscuous mode: accept **all** frames on LAN1 regardless of destination MAC

---

<!-- Slide 10: Demo 7 — Firewall -->
## Demo 7 — Firewall
### Rubric: 2%

**Node3 has a runtime packet filter**

**Step 1 — Confirm connectivity:**
```
Node1:   ping 0x22    →  Node3 replies  ✓
```

**Step 2 — Block Node1:**
```
Node3:   fw add block src 0x12
         fw status
```

**Step 3 — Ping again:**
```
Node1:   ping 0x22    →  No reply  ✗
Node3 log:  [FIREWALL] Dropped packet from 0x12
```

**Step 4 — Remove rule:**
```
Node3:   fw remove block src 0x12
Node1:   ping 0x22    →  Node3 replies again  ✓
```

---

<!-- Slide 11: Open Category Overview -->
## Open Category Features
### What we implemented beyond the requirements

| Feature | Description |
|---------|-------------|
| **DHCP** | Full 4-step handshake, lease management, NAK, expiry |
| **ARP** | Address resolution + cache learning |
| **ARP Spoofing** | Node1 poisons ARP cache for MITM attack |
| **Dynamic ARP Inspection** | LAN validates ARP replies against snooped leases |
| **IDS — IP Spoof Detection** | Cross-LAN source IP mismatch detection |
| **IDS — DHCP Snooping** | Same-LAN MAC↔IP binding verification |
| **IDS — Flood Detection** | Sliding window ping flood detection |
| **Encrypted Messaging** | XOR cipher defeats sniffing |

---

<!-- Slide 12: Demo 8 — Encrypted Messaging -->
## Demo 8 — Encrypted Messaging vs Sniffing
### Open Category

**Node1 is sniffing. Node2 sends a plaintext message:**
```
Node2:   msg 0x22 Secret meeting at 3pm
Node1 intercepts:  "Secret meeting at 3pm"   ← exposed
```

**Node2 sends an encrypted message:**
```
Node2:   emsg 0x22 Secret meeting at 3pm
Node1 intercepts:  "..encrypted bytes.."     ← unreadable
Node3 receives:    "Secret meeting at 3pm"   ← decrypted correctly
```

**How it works:**
- Each byte XOR'd with key `0x5A` before transmission
- Receiver XOR's again to recover original text
- Sniffer sees raw ciphertext with no way to read it

---

<!-- Slide 13: Demo 9+10 — IDS -->
## Demo 9 & 10 — Intrusion Detection System
### Open Category

**Enable IDS on Router:**
```
Router:   ids on
          ids mode passive    (log only, no drops)
```

**Demo 9 — Cross-LAN spoof detection:**
```
Node1:   spoof on 0x22        (claim to be on LAN2)
         ping 0x32
Router IDS alert:  Source IP 0x22 (LAN2) arrived on LAN1 interface — SPOOF DETECTED
```

**Demo 10 — Ping flood detection:**
```
Router:   ids mode active     (now drops suspicious packets)
Node1:    flood 0x32 30
Router IDS alert:  30 pings in 5s from 0x12 — FLOOD DETECTED, dropping
Node4:    stops receiving pings after threshold hit
```

---

<!-- Slide 14: Demo 11 — ARP Spoofing + DAI -->
## Demo 11 — ARP Spoofing + Dynamic ARP Inspection
### Open Category

**The attack:**
```
Node1:   arpspoof 0x13    ← broadcasts forged ARP: "I am 0x13 (Node2)"
Node2's ARP cache poisoned → traffic meant for Node2 goes to Node1
```

**Without defence:** Node1 intercepts Node2's traffic (MITM)

**Enable Dynamic ARP Inspection on LAN1:**
```
LAN1:   dai on
```

**Repeat attack:**
```
Node1:   arpspoof 0x13
LAN1 drops the forged ARP reply:
  [DAI] ARP reply from N1 claiming 0x13 — MISMATCH (snooped: N1→0x12). Dropped.
```

> DAI cross-checks every ARP reply against the DHCP snooping table before forwarding.

---

<!-- Slide 15: Summary -->
## Summary

**A complete, multi-process network simulator with attacks and defences**

<br>

| Layer | What we built |
|-------|--------------|
| Layer 2 (Ethernet) | Broadcast emulation, MAC filtering, ARP |
| Layer 3 (IP) | Custom packet format, multi-LAN routing |
| Application | Ping (ICMP), Text messaging, DHCP |
| **Attack** | IP Spoofing, Sniffing, Ping Flood, ARP Spoofing |
| **Defence** | Firewall, IDS (3 detection modes), DAI, Encryption |

<br>

> All 8 processes run independently and communicate via localhost UDP —
> faithfully emulating a real multi-LAN network environment.

---

<!-- Slide 16: Q&A -->
# Questions?

<br>

**Key things to remember:**
- Routing: high nibble of IP = LAN ID (`0x1_` → LAN1, etc.)
- DHCP snooping = IDS learns MAC↔IP from live lease traffic
- DAI = LAN validates ARP replies against snooped table
- IDS active mode drops; passive mode logs only
- XOR encryption key = `0x5A`

<br>

> _"The best way to understand network security is to break it — and then fix it."_
