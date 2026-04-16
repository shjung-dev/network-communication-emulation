package netemu.device;

import netemu.common.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FirewallTest {

    private Firewall firewall;
    private Log log;

    @BeforeEach
    void setUp() {
        log = new Log("TestFW", Ansi.WHITE);
        firewall = new Firewall(log);
    }

    @Test
    void enabledByDefault() {
        assertTrue(firewall.isEnabled());
    }

    @Test
    void doesNotBlockUnlistedSource() {
        IPPacket packet = IPPacket.icmp(new IPAddress(0x12), new IPAddress(0x22), new byte[10]);
        assertFalse(firewall.shouldBlock(packet));
    }

    @Test
    void blocksListedSource() {
        IPAddress blocked = new IPAddress(0x12);
        firewall.blockSourceIPAddress(blocked);
        IPPacket packet = IPPacket.icmp(blocked, new IPAddress(0x22), new byte[10]);
        assertTrue(firewall.shouldBlock(packet));
    }

    @Test
    void unblockRemovesRule() {
        IPAddress addr = new IPAddress(0x12);
        firewall.blockSourceIPAddress(addr);
        assertTrue(firewall.shouldBlock(
                IPPacket.icmp(addr, new IPAddress(0x22), new byte[10])));

        firewall.unblockSourceIPAddress(addr);
        assertFalse(firewall.shouldBlock(
                IPPacket.icmp(addr, new IPAddress(0x22), new byte[10])));
    }

    @Test
    void disabledFirewallAllowsEverything() {
        IPAddress addr = new IPAddress(0x12);
        firewall.blockSourceIPAddress(addr);
        firewall.setEnabled(false);
        assertFalse(firewall.shouldBlock(
                IPPacket.icmp(addr, new IPAddress(0x22), new byte[10])));
    }

    @Test
    void reEnableFirewallReactivatesRules() {
        IPAddress addr = new IPAddress(0x12);
        firewall.blockSourceIPAddress(addr);
        firewall.setEnabled(false);
        firewall.setEnabled(true);
        assertTrue(firewall.shouldBlock(
                IPPacket.icmp(addr, new IPAddress(0x22), new byte[10])));
    }

    @Test
    void multipleBlockedSources() {
        IPAddress addr1 = new IPAddress(0x12);
        IPAddress addr2 = new IPAddress(0x13);
        IPAddress addr3 = new IPAddress(0x22);
        firewall.blockSourceIPAddress(addr1);
        firewall.blockSourceIPAddress(addr2);

        assertTrue(firewall.shouldBlock(IPPacket.icmp(addr1, new IPAddress(0x22), new byte[10])));
        assertTrue(firewall.shouldBlock(IPPacket.icmp(addr2, new IPAddress(0x22), new byte[10])));
        assertFalse(firewall.shouldBlock(IPPacket.icmp(addr3, new IPAddress(0x12), new byte[10])));
    }

    @Test
    void blockedSourceIPAddressesListIsSnapshot() {
        IPAddress addr = new IPAddress(0x12);
        firewall.blockSourceIPAddress(addr);
        var snapshot = firewall.blockedSourceIPAddressesList();
        assertEquals(1, snapshot.size());
        assertTrue(snapshot.contains(addr));

        // Modifying snapshot doesn't affect firewall
        assertThrows(UnsupportedOperationException.class,
                () -> snapshot.add(new IPAddress(0x99)));
    }

    @Test
    void blockSameIPTwiceIsIdempotent() {
        IPAddress addr = new IPAddress(0x12);
        firewall.blockSourceIPAddress(addr);
        firewall.blockSourceIPAddress(addr);
        assertEquals(1, firewall.blockedSourceIPAddressesList().size());
    }
}
