package netemu.device;

import netemu.common.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IntrusionDetectionSystemTest {

    private IntrusionDetectionSystem ids;
    private Log log;
    private NetworkInterface lan1Interface;
    private NetworkInterface lan2Interface;

    @BeforeEach
    void setUp() {
        log = new Log("TestIDS", Ansi.WHITE);
        ids = new IntrusionDetectionSystem(log);
        lan1Interface = new NetworkInterface(
                AddressTable.MAC_R1, AddressTable.IP_R1, 1,
                AddressTable.ROUTER1_PORT, AddressTable.LAN1_PORT);
        lan2Interface = new NetworkInterface(
                AddressTable.MAC_R2, AddressTable.IP_R2, 2,
                AddressTable.ROUTER2_PORT, AddressTable.LAN2_PORT);

        // Seed the snooping table with the standard node bindings, simulating a
        // post-handshake state where DHCP has handed out the default IPs.
        ids.recordDHCPLease(AddressTable.MAC_N1, AddressTable.IP_N1);
        ids.recordDHCPLease(AddressTable.MAC_N2, AddressTable.IP_N2);
        ids.recordDHCPLease(AddressTable.MAC_N3, AddressTable.IP_N3);
        ids.recordDHCPLease(AddressTable.MAC_N4, AddressTable.IP_N4);
    }

    @Test
    void disabledByDefault() {
        assertFalse(ids.isEnabled());
    }

    @Test
    void disabledDoesNotInspect() {
        // Source IP claims LAN2 but arrives on LAN1 — should be spoofing
        // But IDS is disabled, so should not flag it
        IPPacket packet = IPPacket.icmp(new IPAddress(0x22), new IPAddress(0x32),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = ids.inspect(packet, frame, lan1Interface);
        assertFalse(drop);
        assertEquals(0, ids.spoofAlertCount());
    }

    @Test
    void detectsSpoofInPassiveMode() {
        ids.setEnabled(true);
        ids.setActiveMode(false);

        // Source IP 0x22 (LAN2) arrives on LAN1 interface
        IPPacket packet = IPPacket.icmp(new IPAddress(0x22), new IPAddress(0x32),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = ids.inspect(packet, frame, lan1Interface);
        assertFalse(drop); // passive mode: log only, don't drop
        assertEquals(1, ids.spoofAlertCount());
    }

    @Test
    void detectsSpoofInActiveMode() {
        ids.setEnabled(true);
        ids.setActiveMode(true);

        IPPacket packet = IPPacket.icmp(new IPAddress(0x22), new IPAddress(0x32),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = ids.inspect(packet, frame, lan1Interface);
        assertTrue(drop); // active mode: drop the packet
        assertEquals(1, ids.spoofAlertCount());
    }

    @Test
    void noSpoofAlertForLegitimatePacket() {
        ids.setEnabled(true);
        ids.setActiveMode(true);

        // Source IP 0x12 (LAN1) arrives on LAN1 interface — legitimate
        IPPacket packet = IPPacket.icmp(new IPAddress(0x12), new IPAddress(0x22),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = ids.inspect(packet, frame, lan1Interface);
        assertFalse(drop);
        assertEquals(0, ids.spoofAlertCount());
    }

    @Test
    void sameLanSpoofDetectedViaMacIpBinding() {
        ids.setEnabled(true);
        ids.setActiveMode(true);

        // Node1 (MAC=N1, IP=0x12, LAN1) spoofs as Node2 (IP=0x13, LAN1) — same LAN
        // Cross-LAN check passes (both LAN1), but MAC-IP binding detects the mismatch:
        // MAC N1 is sending with source IP 0x13, but 0x13 belongs to MAC N2
        IPPacket packet = IPPacket.icmp(new IPAddress(0x13), new IPAddress(0x22),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = ids.inspect(packet, frame, lan1Interface);
        assertTrue(drop); // Active mode: detected and dropped
        assertEquals(0, ids.spoofAlertCount()); // Cross-LAN spoof check passes (same LAN)
        assertEquals(1, ids.macIpAlertCount()); // MAC-IP mismatch detected
    }

    @Test
    void floodDetectionTriggersAfterThreshold() {
        ids.setEnabled(true);
        ids.setActiveMode(true);

        IPAddress src = new IPAddress(0x12);
        IPAddress dst = new IPAddress(0x22);

        // Send 9 pings — should not trigger flood
        for (int i = 0; i < 9; i++) {
            IPPacket packet = IPPacket.icmp(src, dst, PingMessage.request(i + 1).encode());
            EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                    packet.encode());
            ids.inspect(packet, frame, lan1Interface);
        }
        assertEquals(0, ids.floodAlertCount());

        // 10th ping should trigger flood detection
        IPPacket packet10 = IPPacket.icmp(src, dst, PingMessage.request(10).encode());
        EthernetFrame frame10 = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet10.encode());
        boolean drop = ids.inspect(packet10, frame10, lan1Interface);
        assertTrue(drop);
        assertTrue(ids.floodAlertCount() >= 1);
    }

    @Test
    void floodDetectionPassiveModeDoesNotDrop() {
        ids.setEnabled(true);
        ids.setActiveMode(false);

        IPAddress src = new IPAddress(0x12);
        IPAddress dst = new IPAddress(0x22);

        for (int i = 0; i < 15; i++) {
            IPPacket packet = IPPacket.icmp(src, dst, PingMessage.request(i + 1).encode());
            EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                    packet.encode());
            boolean drop = ids.inspect(packet, frame, lan1Interface);
            assertFalse(drop); // passive: never drop
        }
        assertTrue(ids.floodAlertCount() >= 1);
    }

    @Test
    void macIpMismatchPassiveModeDoesNotDrop() {
        ids.setEnabled(true);
        ids.setActiveMode(false);

        // Node1 (MAC=N1) spoofs as Node2 (IP=0x13) — passive mode: log but don't drop
        IPPacket packet = IPPacket.icmp(new IPAddress(0x13), new IPAddress(0x22),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = ids.inspect(packet, frame, lan1Interface);
        assertFalse(drop); // passive mode: never drop
        assertEquals(1, ids.macIpAlertCount());
    }

    @Test
    void noMacIpAlertForLegitimatePacket() {
        ids.setEnabled(true);
        ids.setActiveMode(true);

        // Node1 (MAC=N1, IP=0x12) sends with its real IP — no mismatch
        IPPacket packet = IPPacket.icmp(new IPAddress(0x12), new IPAddress(0x22),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = ids.inspect(packet, frame, lan1Interface);
        assertFalse(drop);
        assertEquals(0, ids.macIpAlertCount());
    }

    @Test
    void crossLanSpoofTriggersBothAlerts() {
        ids.setEnabled(true);
        ids.setActiveMode(true);

        // Node1 (MAC=N1, LAN1) spoofs as Node3 (IP=0x22, LAN2)
        // Cross-LAN check: 0x22 claims LAN2, arrived on LAN1 — spoof alert
        // MAC-IP check: N1 sent with IP 0x22, but 0x22 belongs to N3 — MAC-IP alert
        IPPacket packet = IPPacket.icmp(new IPAddress(0x22), new IPAddress(0x32),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = ids.inspect(packet, frame, lan1Interface);
        assertTrue(drop);
        assertEquals(1, ids.spoofAlertCount());
        assertEquals(1, ids.macIpAlertCount());
    }

    @Test
    void snoopedBindingsAreLearnable() {
        IntrusionDetectionSystem freshIds = new IntrusionDetectionSystem(log);
        assertEquals(0, freshIds.snoopedBindingCount());
        freshIds.recordDHCPLease(new MACAddress("X1"), new IPAddress(0x15));
        assertEquals(1, freshIds.snoopedBindingCount());
        freshIds.forgetDHCPLease(new MACAddress("X1"));
        assertEquals(0, freshIds.snoopedBindingCount());
    }

    @Test
    void unknownMacSkipsMacIpCheck() {
        // Fresh IDS, no snooped bindings — a packet with no known MAC should not
        // false-positive the MAC-IP check (e.g., a DHCP client mid-handshake)
        IntrusionDetectionSystem freshIds = new IntrusionDetectionSystem(log);
        freshIds.setEnabled(true);
        freshIds.setActiveMode(true);

        IPPacket packet = IPPacket.icmp(new IPAddress(0x12), new IPAddress(0x22),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("Z9"), new MACAddress("R1"),
                packet.encode());

        boolean drop = freshIds.inspect(packet, frame, lan1Interface);
        assertFalse(drop, "no snooped binding for sender MAC, should not drop");
        assertEquals(0, freshIds.macIpAlertCount());
    }

    @Test
    void macIpCheckUsesSnoopedBindings() {
        // Re-test the spoof case using only snooped bindings (no AddressTable seed).
        IntrusionDetectionSystem freshIds = new IntrusionDetectionSystem(log);
        freshIds.setEnabled(true);
        freshIds.setActiveMode(true);

        // Snoop: MAC N2 holds IP 0x13. MAC N1 then sources a packet from 0x13.
        freshIds.recordDHCPLease(new MACAddress("N2"), new IPAddress(0x13));

        IPPacket packet = IPPacket.icmp(new IPAddress(0x13), new IPAddress(0x22),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = freshIds.inspect(packet, frame, lan1Interface);
        assertTrue(drop);
        assertEquals(1, freshIds.macIpAlertCount());
    }

    @Test
    void senderUsingOwnSnoopedIPIsClean() {
        IntrusionDetectionSystem freshIds = new IntrusionDetectionSystem(log);
        freshIds.setEnabled(true);
        freshIds.setActiveMode(true);

        freshIds.recordDHCPLease(new MACAddress("N1"), new IPAddress(0x12));

        IPPacket packet = IPPacket.icmp(new IPAddress(0x12), new IPAddress(0x22),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = freshIds.inspect(packet, frame, lan1Interface);
        assertFalse(drop);
        assertEquals(0, freshIds.macIpAlertCount());
    }

    @Test
    void forgottenLeaseRemovesProtection() {
        IntrusionDetectionSystem freshIds = new IntrusionDetectionSystem(log);
        freshIds.setEnabled(true);
        freshIds.setActiveMode(true);

        freshIds.recordDHCPLease(new MACAddress("N2"), new IPAddress(0x13));
        freshIds.forgetDHCPLease(new MACAddress("N2"));

        // After forget, N1 sourcing 0x13 is no longer detected because the binding
        // is gone. (Same-LAN spoofing is undetectable without an authority.)
        IPPacket packet = IPPacket.icmp(new IPAddress(0x13), new IPAddress(0x22),
                PingMessage.request(1).encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                packet.encode());

        boolean drop = freshIds.inspect(packet, frame, lan1Interface);
        assertFalse(drop);
        assertEquals(0, freshIds.macIpAlertCount());
    }

    @Test
    void alertCountsAccumulate() {
        ids.setEnabled(true);
        ids.setActiveMode(false);

        // Two spoof attempts
        for (int i = 0; i < 2; i++) {
            IPPacket packet = IPPacket.icmp(new IPAddress(0x22), new IPAddress(0x32),
                    PingMessage.request(i + 1).encode());
            EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"),
                    packet.encode());
            ids.inspect(packet, frame, lan1Interface);
        }
        assertEquals(2, ids.spoofAlertCount());
    }
}
