package netemu.device;

import netemu.common.*;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Intrusion Detection System (IDS) for the router.
 * Detects:
 *  1. IP Spoofing (cross-LAN): Source IP doesn't match expected LAN for incoming interface
 *  2. MAC-IP Mismatch (same-LAN): Source MAC doesn't match expected MAC for source IP,
 *     verified against a snooped binding table populated from observed DHCPACK messages
 *     (real-world DHCP snooping behaviour)
 *  3. Ping Flood: Too many pings from the same source in a certain time window
 *
 * Modes:
 *  - Passive: Log alerts only
 *  - Active: Log alerts AND drops suspicious packets
 */
public class IntrusionDetectionSystem {

    private static final int PING_FLOOD_THRESHOLD = 10;
    private static final long PING_FLOOD_WINDOW_MS = 5000;

    private final Log log;
    private volatile boolean enabled = false;
    private volatile boolean activeMode = false;

    private final AtomicInteger spoofAlerts = new AtomicInteger(0);
    private final AtomicInteger floodAlerts = new AtomicInteger(0);
    private final AtomicInteger macIpAlerts = new AtomicInteger(0);
    private final ConcurrentHashMap<IPAddress, FloodTracker> pingTrackers = new ConcurrentHashMap<>();

    // Snooped MAC -> IP bindings learned from DHCPACK messages flowing through the router.
    // This is the IDS's own ground truth — it does not consult AddressTable, mirroring
    // how a real DHCP-snooping switch maintains its own binding table.
    private final ConcurrentHashMap<MACAddress, IPAddress> snoopedBindings = new ConcurrentHashMap<>();

    public IntrusionDetectionSystem(Log log) {
        this.log = log;
    }

    /**
     * Inspects a packet
     * Returns true if the packet should be dropped (Active mode only)
     */
    public boolean inspect(IPPacket packet, EthernetFrame frame, NetworkInterface incomingNetworkInterfaceCard) {
        if (!enabled) return false;

        // Collect every alert this packet trips so the whole verdict can be
        // emitted as one atomic SECURITY event (alert lines + drop action),
        // keeping multi-trigger alerts visually grouped under concurrency.
        java.util.List<String> alerts = new java.util.ArrayList<>();

        // Check 1: Spoof Detection (cross-LAN)
        // The LAN ID of the source IP Address should match the LAN ID of the incoming interface
        if (packet.sourceIPAddress().lanID() != incomingNetworkInterfaceCard.lanID()) {
            spoofAlerts.incrementAndGet();
            alerts.add("IDS Alert — IP spoof detected: " + packet.sourceIPAddress() + " claims LAN" + packet.sourceIPAddress().lanID() + " but arrived on LAN" + incomingNetworkInterfaceCard.lanID() + " (MAC: " + frame.sourceMACAddress() + ")");
        }

        // Check 2: MAC-IP Binding Verification (same-LAN spoof detection)
        // Look up the source MAC in the snooped binding table. If we have learned
        // a lease for this MAC and the source IP doesn't match, that's a spoof.
        // Conversely, if we see a *different* MAC sourcing an IP we know is leased
        // to someone else, that's also a spoof (the more interesting case for
        // attackers like Node1 using Node2's IP).
        IPAddress snoopedIP = snoopedBindings.get(frame.sourceMACAddress());
        if (snoopedIP != null && !snoopedIP.equals(packet.sourceIPAddress())) {
            macIpAlerts.incrementAndGet();
            alerts.add("IDS Alert — MAC-IP mismatch: " + frame.sourceMACAddress() + " sent packet with source IP " + packet.sourceIPAddress() + " (snooped lease: " + snoopedIP + ")");
        } else {
            // Reverse check: is some other MAC currently leased the source IP?
            for (var entry : snoopedBindings.entrySet()) {
                if (entry.getValue().equals(packet.sourceIPAddress()) && !entry.getKey().equals(frame.sourceMACAddress())) {
                    macIpAlerts.incrementAndGet();
                    alerts.add("IDS Alert — MAC-IP mismatch: " + frame.sourceMACAddress() + " sent packet with source IP " + packet.sourceIPAddress() + " (lease belongs to MAC: " + entry.getKey() + ")");
                    break;
                }
            }
        }

        // Check 3: Ping Flood Detection
        if (packet.protocol() == IPPacket.PROTOCOL_ICMP) {
            PingMessage ping = PingMessage.decode(packet.data());
            if (ping.isRequest()) {
                FloodTracker tracker = pingTrackers.computeIfAbsent(packet.sourceIPAddress(), k -> new FloodTracker());
                if (tracker.recordAndCheck()) {
                    floodAlerts.incrementAndGet();
                    alerts.add("IDS Alert — Ping flood detected: " + tracker.recentCount() + " pings from " + packet.sourceIPAddress() + " in " + PING_FLOOD_WINDOW_MS + "ms (threshold: " + PING_FLOOD_THRESHOLD + ")");
                }
            }
        }

        if (alerts.isEmpty()) return false;

        boolean drop = activeMode;
        if (drop) {
            alerts.add("IDS Action — Dropped packet from " + packet.sourceIPAddress());
        }
        // Atomic security event so the alert lines + drop verdict stay together.
        String first = alerts.get(0);
        String[] rest = alerts.subList(1, alerts.size()).toArray(new String[0]);
        log.securityEvent(first, rest);
        return drop;
    }

    /**
     * Record a DHCP lease observed flowing through the router. Called by the router
     * whenever the local DHCP server emits an ACK. The IDS uses these snooped
     * bindings as ground truth for MAC-IP verification.
     */
    public void recordDHCPLease(MACAddress mac, IPAddress ip) {
        snoopedBindings.put(mac, ip);
        log.info("IDS snoop: learned " + mac + " -> " + ip);
    }

    /**
     * Forget a snooped binding (e.g., on lease release).
     */
    public void forgetDHCPLease(MACAddress mac) {
        IPAddress removed = snoopedBindings.remove(mac);
        if (removed != null) {
            log.info("IDS snoop: forgot " + mac + " -> " + removed);
        }
    }

    public int snoopedBindingCount() {
        return snoopedBindings.size();
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setActiveMode(boolean active) {
        this.activeMode = active;
    }

    public boolean isActiveMode() {
        return activeMode;
    }

    public int spoofAlertCount() {
        return spoofAlerts.get();
    }

    public int floodAlertCount() {
        return floodAlerts.get();
    }

    public int macIpAlertCount() {
        return macIpAlerts.get();
    }

    public void printStatus() {
        // Build the full status box first, then emit it as one atomic block so
        // concurrent receiver/security log lines can't break it up.
        java.util.List<String> lines = new java.util.ArrayList<>();
        lines.add("┌─ IDS Status ──────────────────────────");
        lines.add("│  State          : " + (enabled ? "ON  (monitoring)" : "OFF (disabled)"));
        lines.add("│  Mode           : " + (activeMode ? "ACTIVE  (log + drop)" : "PASSIVE (log only)"));
        lines.add("│  Snooped leases : " + snoopedBindings.size());
        if (snoopedBindings.isEmpty()) {
            lines.add("│    (none)");
        } else {
            for (var entry : snoopedBindings.entrySet()) {
                lines.add("│    • " + entry.getKey() + "  →  " + entry.getValue());
            }
        }
        lines.add("│  Alert counters :");
        lines.add("│    • Spoof   : " + spoofAlerts.get());
        lines.add("│    • MAC-IP  : " + macIpAlerts.get());
        lines.add("│    • Flood   : " + floodAlerts.get());
        lines.add("└───────────────────────────────────────");
        log.block(lines.toArray(new String[0]));
    }

    /*
     * Tracks ping counts within a sliding time window
     */
    static class FloodTracker {
        private final long[] timestamps = new long[100];
        private int head = 0;
        private int count = 0;

        synchronized boolean recordAndCheck() {
            long now = System.currentTimeMillis();
            timestamps[head] = now;
            head = (head + 1) % timestamps.length;
            if (count < timestamps.length) count++;

            // Count pings within the window
            int recent = 0;
            for (int i = 0; i < count; i++) {
                if (now - timestamps[i] <= PING_FLOOD_WINDOW_MS) {
                    recent++;
                }
            }
            return recent >= PING_FLOOD_THRESHOLD;
        }

        synchronized int recentCount() {
            long now = System.currentTimeMillis();
            int recent = 0;
            for (int i = 0; i < count; i++) {
                if (now - timestamps[i] <= PING_FLOOD_WINDOW_MS) {
                    recent++;
                }
            }
            return recent;
        }
    }
}
