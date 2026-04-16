# CS441 Network Emulator — Demo Presentation Guide

**Duration:** 20 min demo + 10 min Q&A  
**Format:** Live terminal demo across 8 processes

---

## Before You Start

### Build
```bash
mvn clean package
```

### Open 8 terminal windows and label them:
| Terminal | Process |
|----------|---------|
| T1 | LAN1 Emulator |
| T2 | LAN2 Emulator |
| T3 | LAN3 Emulator |
| T4 | Router |
| T5 | Node1 (Attacker) |
| T6 | Node2 (Normal) |
| T7 | Node3 (Firewall) |
| T8 | Node4 (Normal) |

### Startup order (strict — do NOT skip steps)
```bash
# T1
java -cp target/netemu-1.0-SNAPSHOT.jar netemu.lan.LAN1

# T2
java -cp target/netemu-1.0-SNAPSHOT.jar netemu.lan.LAN2

# T3
java -cp target/netemu-1.0-SNAPSHOT.jar netemu.lan.LAN3

# T4
java -cp target/netemu-1.0-SNAPSHOT.jar netemu.device.Router

# T5 — wait for DHCP ACK before starting T6
java -cp target/netemu-1.0-SNAPSHOT.jar netemu.device.Node1

# T6 — wait for DHCP ACK before starting T7
java -cp target/netemu-1.0-SNAPSHOT.jar netemu.device.Node2

# T7 — wait for DHCP ACK before starting T8
java -cp target/netemu-1.0-SNAPSHOT.jar netemu.device.Node3

# T8
java -cp target/netemu-1.0-SNAPSHOT.jar netemu.device.Node4
```

> **Tip:** Start nodes one at a time and wait for the `DHCP: ACK` line before starting the next one. This ensures predictable IP assignment: Node1=`0x12`, Node2=`0x13`, Node3=`0x22`, Node4=`0x32`.

---

## Presentation Flow

---

## Part 1 — Introduction (2 min)

**What to say:**
- This project emulates a simplified IP-over-Ethernet network in software using Java UDP sockets.
- Each device runs as a separate process. There are 3 LANs, 1 Router, and 4 Nodes.
- We implemented all required protocols plus several open-category security features.

**Point to the topology on screen (T4 Router banner):**
```
Router interfaces: R1 (LAN1, 0x11), R2 (LAN2, 0x21), R3 (LAN3, 0x31)
LAN1: Node1 (0x12, attacker), Node2 (0x13, normal)
LAN2: Node3 (0x22, firewall)
LAN3: Node4 (0x32, normal)
```

---

## Part 2 — DHCP Boot (Open Category) (2 min)

> **Show this first** — it proves the network is live and demonstrates the open-category DHCP feature before anything else.

**What to show:** The startup logs already on screen from when nodes booted.

**On T4 (Router), scroll up to show:**
```
DHCP[LAN1]: offering 0x12 to N1
DHCP[LAN1]: ACK — leased 0x12 to N1 for 60s
IDS snoop: learned N1 -> 0x12
DHCP[LAN1]: ACK — leased 0x13 to N2 for 60s
IDS snoop: learned N2 -> 0x13
...
```

**What to say:**
- Nodes don't have hardcoded IPs. On startup, each runs a full DHCP handshake: DISCOVER → OFFER → REQUEST → ACK.
- The Router hosts one DHCP server per LAN interface and hands out leases from a per-LAN pool.
- Every successful lease is immediately fed into the IDS as a trusted MAC↔IP binding — this is DHCP snooping.

---

## Part 3 — Basic Network Emulation (5 min)

### 3a. Ethernet Broadcast + MAC Filtering (1.5 min)

**What to show:** When Node2 pings Node1 (same LAN), both Node1 and Router R1 receive the frame — but R1 drops it because the destination MAC is `N1`, not `R1`.

**On T6 (Node2):**
```
ping 0x12
```

**Point to T5 (Node1):** receives and processes the ping  
**Point to T4 (Router):** receives the frame but drops it (MAC mismatch — destination is `N1`, not `R1`)

**What to say:**
- The LAN emulator broadcasts the frame to all devices on LAN1, just like real Ethernet.
- Each device checks: "Is this frame for me?" If not, it drops it — that's MAC filtering.

---

### 3b. IP Routing / Packet Forwarding (2 min)

**What to show:** A cross-LAN ping that travels through the Router.

**On T5 (Node1):**
```
ping 0x32
```

**Walk through what happens:**
1. Node1 sends frame to Router R1 (destination MAC = `R1`)
2. Router receives on LAN1 interface, reads destination IP `0x32`
3. High nibble `0x3` → LAN3, so forward out R3 interface
4. Router re-wraps packet in a new Ethernet frame (src=`R3`, dst=`N4`) and sends to LAN3
5. Node4 receives and replies

**Point to:** T5 (Node1 TX), T4 (Router forwarding log), T8 (Node4 RX + reply)

**What to say:**
- The routing rule is simple: the high nibble of the IP address is the LAN ID. No routing protocol needed.
- Notice the Ethernet frame is completely replaced at the router — different MACs on each LAN segment.

---

### 3c. Ping with RTT (30 sec)

**On T6 (Node2):**
```
ping 0x22 count 3
```

**Point to:** RTT printed on T6 after each reply.

---

## Part 4 — IP Spoofing Attack (2 min)

> Covers the 2% IP Spoofing rubric requirement.

**On T5 (Node1), enable spoofing to impersonate Node2:**
```
spoof on 0x13
ping 0x22
```

**Point to T7 (Node3):**
- Incoming packet shows source IP `0x13` (Node2's address)
- But it was actually sent by Node1

**What to say:**
- Node1 simply overwrites the source IP field in the outgoing packet with `0x13`.
- From Node3's perspective, the packet looks like it came from Node2.
- This is a classic IP spoofing attack — the receiver cannot tell who really sent it.

**Then turn it off:**
```
spoof off
```

---

## Part 5 — Sniffing Attack (1.5 min)

> Covers the 1% Sniffing rubric requirement.

**On T5 (Node1), enable promiscuous mode:**
```
sniff on
```

**On T6 (Node2), send a message to Node3:**
```
msg 0x22 Hello from Node2
```

**Point to T5 (Node1):**
- Node1 intercepts and reads the message even though it was addressed to Node3

**What to say:**
- In normal mode, Node1 drops any frame not addressed to MAC `N1`.
- In promiscuous (sniff) mode, it accepts all frames on LAN1 — including Node2's private messages.
- This is how a rogue device on the same LAN can eavesdrop on all traffic.

---

## Part 6 — Firewall (2 min)

> Covers the 2% Firewall rubric requirement.

**Setup: Node1 is still on the same LAN. We'll try to reach Node3 from Node1, then block it.**

**On T5 (Node1):**
```
ping 0x22
```
*Confirm: Node3 receives the ping.*

**On T7 (Node3), add a block rule:**
```
fw add block src 0x12
fw status
```

**On T5 (Node1), try again:**
```
ping 0x22
```

**Point to T7 (Node3):** packet is dropped, firewall log entry appears, no ping reply  
**Point to T5 (Node1):** no reply received (timeout)

**Then remove the rule:**
```
fw remove block src 0x12
```

**Ping again from T5 — now it goes through.**

**What to say:**
- The firewall on Node3 checks every incoming packet's source IP against its blocklist.
- Rules are added and removed at runtime with no restart needed.

---

## Part 7 — Open Category Features (6 min)

---

### 7a. Encrypted Messaging vs Sniffing (1.5 min)

> Shows defense against sniffing — contrast with Part 5.

**Node1 is still sniffing (if not, re-enable with `sniff on` on T5).**

**On T6 (Node2), send an encrypted message:**
```
emsg 0x22 Secret message
```

**Point to T5 (Node1):** sees only garbled ciphertext bytes — cannot read the content  
**Point to T7 (Node3):** receives and decrypts the message correctly

**What to say:**
- The plaintext is XOR-encrypted with a shared key before transmission.
- Even though Node1 intercepts the frame, it sees only encrypted bytes.
- This demonstrates that encryption defeats passive sniffing.

---

### 7b. IDS — IP Spoof Detection (1.5 min)

**On T4 (Router), enable IDS:**
```
ids on
ids mode passive
```

**On T5 (Node1), spoof with a LAN2 IP and ping Node4:**
```
spoof on 0x22
ping 0x32
spoof off
```

**Point to T4 (Router):**
- IDS alert: source IP `0x22` (LAN2) arrived on LAN1 interface — cross-LAN spoof detected

**What to say:**
- The IDS checks: does the source IP's LAN ID match the interface the packet arrived on?
- A packet claiming to be from `0x22` (LAN2) but arriving on the LAN1 interface is structurally impossible — it must be spoofed.

---

### 7c. IDS — Ping Flood Detection (1.5 min)

**On T4 (Router), switch to active mode:**
```
ids mode active
```

**On T5 (Node1), flood Node4:**
```
flood 0x32 30
```

**Point to T4 (Router):**
- After 10 pings within 5 seconds, IDS logs flood alert
- In active mode, subsequent packets from Node1 are dropped

**Point to T8 (Node4):** stops receiving pings after IDS kicks in

**What to say:**
- The IDS tracks ICMP requests per source IP in a sliding 5-second window.
- Threshold is 10 requests — above that it's flagged as a flood.
- In active mode it drops the packets; in passive mode it only logs.

---

### 7d. ARP Spoofing + DAI (1.5 min)

**On T5 (Node1), trigger ARP spoofing:**
```
arpspoof 0x13
```
*(Node1 claims to be Node2 by broadcasting forged ARP replies)*

**Point to T6 (Node2):** ARP cache gets poisoned — traffic intended for Node2 now goes to Node1

**On T1 (LAN1), enable Dynamic ARP Inspection:**
```
dai on
```

**Repeat the ARP spoof:**
```
arpspoof 0x13
```

**Point to T1 (LAN1):** DAI detects the forged ARP reply (MAC-IP mismatch against snooped table) and drops it

**What to say:**
- ARP spoofing lets an attacker redirect traffic by poisoning the ARP cache of other nodes.
- Dynamic ARP Inspection on the LAN emulator cross-checks every ARP reply against the DHCP snooping table.
- If the claimed IP doesn't match the sender's snooped lease, the frame is dropped before it reaches any node.

---

## Part 8 — Wrap-up (30 sec)

**Summary table to mention:**

| Rubric Item | Feature | Status |
|-------------|---------|--------|
| Ethernet (2%) | Broadcast + MAC filter | Done |
| IP (3%) | Packet format + addressing | Done |
| Forwarding (2%) | Fixed routing table | Done |
| Ping (1%) | ICMP echo + RTT | Done |
| IP Spoofing (2%) | Node1 forges source IP | Done |
| Sniffing (1%) | Node1 promiscuous mode | Done |
| Firewall (2%) | Node3 runtime rules | Done |
| Open Category (8%) | DHCP, ARP Spoofing, DAI, IDS, Encrypted Messaging | Done |

---

## Q&A Preparation (10 min)

### On Basic Networking

**Q: Why UDP for the emulation instead of TCP?**  
A: UDP is connectionless and unreliable — just like real Ethernet. Using TCP would add delivery guarantees and connection state that Ethernet doesn't have, which would give a false picture of how the protocol actually works.

**Q: How does routing work without a routing protocol?**  
A: We use a fixed rule: the high nibble of the destination IP encodes the LAN ID (`0x1_` = LAN1, `0x2_` = LAN2, `0x3_` = LAN3). The router reads this nibble and forwards to the matching interface. No dynamic routing needed.

**Q: How is Ethernet broadcast emulated?**  
A: Each LAN runs as a separate Java process. When a node sends a frame, it sends it to the LAN emulator via UDP. The emulator maintains a registry of all devices on that LAN and fans the frame out to every registered endpoint except the sender.

**Q: What happens to frames not addressed to a device?**  
A: Every node checks the destination MAC in the frame header. If it doesn't match its own MAC (and isn't `FF` broadcast), the frame is dropped silently — that's the MAC filtering step.

---

### On Security Features

**Q: How does IP spoofing work in your implementation?**  
A: Node1 simply sets the source IP field in the outgoing IP packet to any value it wants before sending. There's nothing in the protocol to prevent this — IP has no source authentication.

**Q: How does the IDS detect cross-LAN IP spoofing?**  
A: It checks the source IP of every forwarded packet against the interface it arrived on. If source IP `0x22` (LAN2) arrives on the LAN1 interface, that's structurally impossible in a real network — the packet must have forged its source IP.

**Q: How does DHCP snooping work?**  
A: The IDS passively observes all DHCP ACK messages flowing through the router. For each ACK, it records the MAC-to-IP binding as a trusted entry. For every forwarded packet, it verifies the source MAC and source IP against this table. A mismatch means the sender is lying about its identity.

**Q: What's the difference between IDS passive and active mode?**  
A: Passive mode logs the alert but still forwards the packet. Active mode drops the packet in addition to logging. Passive is useful for monitoring without disrupting traffic; active is used to actually block attacks.

**Q: How does DAI (Dynamic ARP Inspection) prevent ARP spoofing?**  
A: The LAN emulator intercepts all ARP reply frames before broadcasting them. It validates the sender's claimed IP against the same DHCP snooping table. If a node claims an IP it wasn't leased, the ARP reply is dropped before any other node on the LAN sees it.

**Q: Can your IDS detect same-LAN IP spoofing?**  
A: Yes — through DHCP snooping. If Node1 spoofs Node2's IP (`0x13`) but sends the packet with its own MAC (`N1`), the IDS sees that MAC `N1` has a snooped lease for `0x12`, not `0x13`. Mismatch is flagged. This is the same technique used by managed switches in real networks.

---

### On Open Category

**Q: Why is DHCP significant for this project?**  
A: Most student implementations use hardcoded/static IPs. DHCP is how real networks assign addresses dynamically. We implemented the full 4-step handshake, lease management with expiry, NAK responses, and the integration between DHCP leases and the IDS snooping table.

**Q: How does XOR encryption help against sniffing?**  
A: The plaintext payload is XOR'd byte-by-byte with a shared key (0x5A) before transmission. A sniffer intercepting the frame sees only the encrypted bytes. The receiver, which knows the key, XOR's again to recover the original text. It's a simple cipher for demonstration purposes.

**Q: Why did you implement ARP in addition to what was required?**  
A: ARP is essential for realistic LAN communication — nodes need to resolve destination IPs to MAC addresses before they can send frames. It also enables the ARP spoofing attack and DAI defense, which demonstrate a realistic MITM scenario that goes beyond the basic requirements.

---

## Quick Reference: Key Commands

| Terminal | Key Commands for Demo |
|----------|-----------------------|
| Node1 (T5) | `spoof on 0x13` / `spoof off`, `sniff on` / `sniff off`, `flood 0x32 30`, `arpspoof 0x13` |
| Node2 (T6) | `ping 0x12`, `ping 0x22`, `msg 0x22 Hello`, `emsg 0x22 Secret` |
| Node3 (T7) | `fw add block src 0x12`, `fw remove block src 0x12`, `fw status` |
| Router (T4) | `ids on`, `ids mode active`, `ids mode passive`, `ids status` |
| LAN1 (T1) | `dai on`, `dai off` |
