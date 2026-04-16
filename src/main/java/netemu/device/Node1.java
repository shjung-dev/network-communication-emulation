package netemu.device;

import netemu.common.*;
import java.io.IOException;

/**
 * Node 1
 *  - Role: Attacker in LAN1
 *  - MAC Address: N1
 *  - IP Address: 0x12
 *  - Port Number: 6001
 *  - LAN ID: 1
 */
public class Node1 extends Node {
    
    private volatile boolean spoofing = false;
    private volatile boolean sniffing = false;
    private volatile IPAddress spoofIPAddress = null;
    private volatile boolean arpSpoofing = false;
    private volatile IPAddress arpSpoofVictimIPAddress = null;
    private volatile IPAddress arpSpoofClaimedIPAddress = null;
    private volatile boolean arpPoisonLoopStarted = false;

    public Node1() {
        super("Node1", new NetworkInterface(AddressTable.MAC_N1, AddressTable.IP_N1, 1, AddressTable.NODE1_PORT, AddressTable.LAN1_PORT), Ansi.RED);
    }

    @Override
    protected String logColor() {
        return Ansi.RED;
    }

    @Override
    protected void handleFrame(EthernetFrame frame) {
        // SNIFFING MODE — log the full frame → packet → inner-message tree
        // atomically so concurrent receiver/CLI activity can't break it apart.
        if (sniffing && !frame.destinationMACAddress().equals(networkInterfaceCard.macAddress())) {
            try {
                IPPacket packet = IPPacket.decode(frame.data());
                String inner = sniffInner(packet);
                if (inner != null) {
                    log.event("[Sniffed] " + frame, "  └─ " + packet, inner);
                } else {
                    log.event("[Sniffed] " + frame, "  └─ " + packet);
                }
            } catch (Exception e) {
                // Invalid IP packet — still log the raw frame so the operator sees it
                log.event("[Sniffed] " + frame);
            }
        }
        // Normal MAC filtering for processing
        if (frame.destinationMACAddress().equals(networkInterfaceCard.macAddress()) || frame.destinationMACAddress().isBroadcast()) {
            processFrame(frame);
        }
    }

    /**
     * Render the inner protocol message of a sniffed packet. Differs from
     * {@code Node.describeInner} in that text messages use {@code decodeRaw}
     * so encrypted traffic stays encrypted in the sniffer's view.
     */
    private String sniffInner(IPPacket packet) {
        try {
            return switch (packet.protocol()) {
                case IPPacket.PROTOCOL_ICMP -> "     └─ " + PingMessage.decode(packet.data());
                case IPPacket.PROTOCOL_DATA -> {
                    TextMessage msg = TextMessage.decodeRaw(packet.data());
                    yield "     └─ " + msg + (msg.isEncrypted() ? " (cannot read — encrypted)" : "");
                }
                case IPPacket.PROTOCOL_DHCP -> "     └─ " + DHCPMessage.decode(packet.data());
                case IPPacket.PROTOCOL_ARP  -> "     └─ " + ARPMessage.decode(packet.data());
                default -> null;
            };
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Intercept ARP requests for the claimed IP (e.g. the router) and respond with a forged reply,
     * mapping the claimed IP to Node1's MAC address.
     */
    @Override
    protected void handleArp(IPPacket packet, EthernetFrame frame) {
        ARPMessage arp = ARPMessage.decode(packet.data());
        arpCache.put(arp.senderIP(), arp.senderMAC());

        if (arpSpoofing && arp.isRequest() && arpSpoofClaimedIPAddress != null
                && arp.targetIP().equals(arpSpoofClaimedIPAddress)) {
            log.warn("[ARP Spoof] Intercepted ARP request for " + arpSpoofClaimedIPAddress
                    + " from " + arp.senderIP() + " — sending forged reply");
            ARPMessage forgedReply = ARPMessage.reply(arpSpoofClaimedIPAddress, networkInterfaceCard.macAddress(), arp.senderIP());
            IPPacket replyPacket = IPPacket.arp(arpSpoofClaimedIPAddress, arp.senderIP(), forgedReply.encode());
            EthernetFrame replyFrame = new EthernetFrame(networkInterfaceCard.macAddress(), frame.sourceMACAddress(), replyPacket.encode());
            try {
                sendFrame(replyFrame, lanEmulatorAddress);
            } catch (IOException e) {
                log.error("ARP spoof reply failed: " + e.getMessage());
            }
            return;
        }
        super.handleArp(packet, frame);
    }

    /**
     * MITM forwarding: when arpSpoofing is ON and a packet arrives at Node1 that is destined for
     * another host (because the victim's ARP cache was poisoned), re-encapsulate it with the real
     * router MAC and forward it so the victim's communication is preserved (man-in-the-middle).
     */
    @Override
    protected void handleIPPacket(IPPacket packet, EthernetFrame frame) {
        if (arpSpoofing
                && !packet.destinationIPAddress().equals(networkInterfaceCard.ipAddress())
                && !packet.destinationIPAddress().equals(DHCPMessage.BROADCAST_IP)
                && packet.protocol() != IPPacket.PROTOCOL_ARP
                && packet.protocol() != IPPacket.PROTOCOL_DHCP
                && frame.destinationMACAddress().equals(networkInterfaceCard.macAddress())) {
            log.warn("[MITM] Intercepted: " + packet.sourceIPAddress() + " \u2192 " + packet.destinationIPAddress());

            if (packet.protocol() == IPPacket.PROTOCOL_DATA) {
                try {
                    TextMessage intercepted = TextMessage.decodeRaw(packet.data());
                    if (intercepted.isEncrypted()) {
                        log.warn("[MITM] Payload (encrypted): \"" + intercepted.text() + "\"");
                    } else {
                        log.warn("[MITM] Payload: \"" + intercepted.text() + "\"");
                    }
                } catch (Exception e) {
                    log.warn("[MITM] Payload decode failed: " + e.getMessage());
                }
            }

            EthernetFrame forwardFrame = new EthernetFrame(networkInterfaceCard.macAddress(), AddressTable.MAC_R1, packet.encode());
            try {
                sendFrame(forwardFrame, lanEmulatorAddress);
                log.warn("[MITM] Forwarded to Router (R1)");
            } catch (IOException e) {
                log.error("MITM forward failed: " + e.getMessage());
            }
            return;
        }
        super.handleIPPacket(packet, frame);
    }

    @Override
    protected void sendIPPacket(IPPacket packet) {
        if (spoofing && spoofIPAddress != null) {
            // Replace source IP Address with spoofed IP Address
            IPPacket spoofedPacket = new IPPacket(spoofIPAddress, packet.destinationIPAddress(), packet.protocol(), packet.data());
            log.warn("Spoofed packet: pretending to be " + spoofIPAddress + " (real IP: " + networkInterfaceCard.ipAddress() + ")");
            super.sendIPPacket(spoofedPacket);
        } else {
            super.sendIPPacket(packet);
        }
    }

    @Override
    protected boolean handleCommand(String line) {
        String[] parts = line.split("\\s+");
        String cmd = parts[0].toLowerCase();

        return switch (cmd) {
            case "spoof" -> { handleSpoofCommand(parts); yield true; }
            case "arpspoof" -> { handleArpSpoofCommand(parts); yield true; }
            case "sniff" -> { handleSniffCommand(parts); yield true; }
            case "flood" -> { handleFloodCommand(parts); yield true; }
            default -> super.handleCommand(line);
        };
    }

    private void handleArpSpoofCommand(String[] parts) {
        if (parts.length < 2) {
            System.out.println("Usage: arpspoof on <victimIP> <claimedIP> | off | once <victimIP> <claimedIP>");
            return;
        }

        switch (parts[1].toLowerCase()) {
            case "on" -> {
                if (parts.length < 4) {
                    System.out.println("Usage: arpspoof on <victimIP> <claimedIP>");
                    return;
                }
                arpSpoofVictimIPAddress = IPAddress.parse(parts[2]);
                arpSpoofClaimedIPAddress = IPAddress.parse(parts[3]);
                arpSpoofing = true;
                log.warn("ARP spoofing ON — poisoning " + arpSpoofVictimIPAddress + " with claim " + arpSpoofClaimedIPAddress + " is-at " + networkInterfaceCard.macAddress());
                startArpPoisonLoopIfNeeded();
            }
            case "off" -> {
                arpSpoofing = false;
                arpSpoofVictimIPAddress = null;
                arpSpoofClaimedIPAddress = null;
                log.info("ARP spoofing OFF");
            }
            case "once" -> {
                if (parts.length < 4) {
                    System.out.println("Usage: arpspoof once <victimIP> <claimedIP>");
                    return;
                }
                IPAddress victim = IPAddress.parse(parts[2]);
                IPAddress claimed = IPAddress.parse(parts[3]);
                sendForgedArpReply(victim, claimed);
            }
            default -> System.out.println("Usage: arpspoof on <victimIP> <claimedIP> | off | once <victimIP> <claimedIP>");
        }
    }

    private void startArpPoisonLoopIfNeeded() {
        if (arpPoisonLoopStarted) {
            return;
        }
        arpPoisonLoopStarted = true;
        Thread t = new Thread(() -> {
            while (true) {
                try {
                    if (arpSpoofing && arpSpoofVictimIPAddress != null && arpSpoofClaimedIPAddress != null) {
                        sendForgedArpReply(arpSpoofVictimIPAddress, arpSpoofClaimedIPAddress);
                    }
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {
                }
            }
        }, "Node1-arp-spoof");
        t.setDaemon(true);
        t.start();
    }

    private void sendForgedArpReply(IPAddress victimIPAddress, IPAddress claimedIPAddress) {
        try {
            MACAddress victimMACAddress = arpCache.get(victimIPAddress);
            if (victimMACAddress == null) {
                victimMACAddress = AddressTable.resolve(victimIPAddress).orElse(null);
            }
            if (victimMACAddress == null) {
                log.error("Failed ARP spoof send: unknown victim " + victimIPAddress);
                return;
            }
            ARPMessage forged = ARPMessage.reply(claimedIPAddress, networkInterfaceCard.macAddress(), victimIPAddress);
            IPPacket packet = IPPacket.arp(claimedIPAddress, victimIPAddress, forged.encode());
            EthernetFrame frame = new EthernetFrame(networkInterfaceCard.macAddress(), victimMACAddress, packet.encode());
            sendFrame(frame, lanEmulatorAddress);
            log.warn("Sent forged ARP reply to " + victimIPAddress + ": " + claimedIPAddress + " is-at " + networkInterfaceCard.macAddress());
        } catch (Exception e) {
            log.error("Failed ARP spoof send: " + e.getMessage());
        }
    }

    private void handleSpoofCommand(String[] parts) {
        if (parts.length < 2) {
            System.out.println("Usage: spoof on <IP> | spoof off");
            return;
        }
        switch (parts[1].toLowerCase()) {
            case "on" -> {
                if (parts.length >= 3) {
                    spoofIPAddress = IPAddress.parse(parts[2]);
                    spoofing = true;
                    log.warn("Spoofing ON — now impersonating " + spoofIPAddress);
                } else {
                    System.out.println("Usage: Spoof on <IP>");
                }
            }
            case "off" -> {
                spoofing = false;
                spoofIPAddress= null;
                log.info("Spoofing OFF — using real IP");
            }
            default -> System.out.println("Usage: Spoof on <IP> | spoof off");
        }
    }

    private void handleSniffCommand(String[] parts) {
        if (parts.length < 2) {
            System.out.println("Usage: sniff on | sniff off");
            return;
        }
        switch (parts[1].toLowerCase()) {
            case "on" -> {
                sniffing = true;
                log.warn("Sniffing ON — capturing all LAN" + networkInterfaceCard.lanID() + " traffic");
            }
            case "off" -> {
                sniffing = false;
                log.info("Sniffing OFF");
            }
            default -> System.out.println("Usage: sniff on | sniff off");
        }
    }

    private void handleFloodCommand(String[] parts) {
        if (parts.length < 3) {
            System.out.println("Usage: flood <destIP> <count>");
            return;
        }
        IPAddress destinationIPAddress = IPAddress.parse(parts[1]);
        int count = Integer.parseInt(parts[2]);

        log.warn("Flood attack: sending " + count + " rapid pings to " + destinationIPAddress);
        for (int i = 0; i < count; i++) {
            PingMessage ping = PingMessage.request(i + 1);
            IPPacket packet = IPPacket.icmp(
                    spoofing && spoofIPAddress != null ? spoofIPAddress : networkInterfaceCard.ipAddress(),
                    destinationIPAddress, ping.encode());
            super.sendIPPacket(packet);
        }
        log.warn("Flood attack complete: " + count + " pings sent");
    }

    @Override
    protected void appendExtraHelp(java.util.List<String> lines) {
        lines.add("│  ─── attacker actions ───");
        lines.add("│  spoof on <IP> | off         Enable/disable IP spoofing");
        lines.add("│  arpspoof on <victim> <ip>   Continuously poison victim ARP cache");
        lines.add("│  arpspoof once <victim> <ip> Send one forged ARP reply");
        lines.add("│  arpspoof off                Disable ARP spoofing");
        lines.add("│  sniff on | off              Enable/disable promiscuous sniffing");
        lines.add("│  flood <destIP> <count>      Send ping flood");
    }

    public static void main(String[] args) throws IOException {
        boolean useStatic = args.length > 0 && "--static".equalsIgnoreCase(args[0]);
        new Node1().start(!useStatic);
    }
}
