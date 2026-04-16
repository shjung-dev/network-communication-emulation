package netemu.device;

import netemu.common.AddressTable;
import netemu.common.Ansi;
import netemu.common.DHCPMessage;
import netemu.common.IPAddress;
import netemu.common.Log;
import netemu.common.MACAddress;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class DHCPServerTest {

    private Log log;
    private DHCPServer server;
    private long now;

    @BeforeEach
    void setUp() {
        log = new Log("TestDHCP", Ansi.WHITE);
        // Clear any node bindings the static AddressTable seeded so the LAN1 pool
        // is genuinely empty before each test.
        AddressTable.unbind(AddressTable.IP_N1);
        AddressTable.unbind(AddressTable.IP_N2);
        server = new DHCPServer(1, AddressTable.IP_R1, 60, log);
        now = 1_000_000L;
    }

    @AfterEach
    void tearDown() {
        // Restore the static seed so other tests aren't affected
        AddressTable.bind(AddressTable.IP_N1, AddressTable.MAC_N1, 1);
        AddressTable.bind(AddressTable.IP_N2, AddressTable.MAC_N2, 1);
        // Unbind anything the server might have leased
        for (IPAddress ip : AddressTable.lanPool(1)) {
            if (!ip.equals(AddressTable.IP_N1) && !ip.equals(AddressTable.IP_N2) && !ip.equals(AddressTable.IP_R1)) {
                AddressTable.unbind(ip);
            }
        }
    }

    @Test
    void poolExcludesGateway() {
        // LAN1 pool would be 0x12..0x1F (14 addresses); router 0x11 is not in pool
        assertEquals(14, server.poolSize());
    }

    @Test
    void discoverProducesOffer() {
        DHCPMessage discover = DHCPMessage.discover(0x1234, new MACAddress("N1"));
        Optional<DHCPMessage> response = server.handle(discover, now);
        assertTrue(response.isPresent());
        DHCPMessage offer = response.get();
        assertTrue(offer.isOffer());
        assertEquals(0x1234, offer.xid());
        assertEquals("N1", offer.clientMAC().value());
        assertEquals(1, offer.yourIP().lanID());
        assertEquals(AddressTable.IP_R1, offer.serverIP());
        assertEquals(60, offer.leaseSecs());
    }

    @Test
    void requestAfterOfferProducesAck() {
        DHCPMessage discover = DHCPMessage.discover(0x1, new MACAddress("N1"));
        DHCPMessage offer = server.handle(discover, now).orElseThrow();

        DHCPMessage request = DHCPMessage.request(0x1, new MACAddress("N1"), offer.yourIP(), offer.serverIP());
        DHCPMessage ack = server.handle(request, now).orElseThrow();

        assertTrue(ack.isAck());
        assertEquals(offer.yourIP(), ack.yourIP());
        assertEquals(60, ack.leaseSecs());
        assertEquals(1, server.leaseCount());
    }

    @Test
    void ackUpdatesAddressTable() {
        DHCPMessage offer = server.handle(DHCPMessage.discover(0x1, new MACAddress("N1")), now).orElseThrow();
        server.handle(DHCPMessage.request(0x1, new MACAddress("N1"), offer.yourIP(), offer.serverIP()), now).orElseThrow();

        assertEquals(new MACAddress("N1"), AddressTable.resolve(offer.yourIP()).orElseThrow());
        assertEquals(1, AddressTable.getLANForIP(offer.yourIP()));
    }

    @Test
    void requestForUnknownIPProducesNak() {
        DHCPMessage request = DHCPMessage.request(0x1, new MACAddress("N1"), new IPAddress(0x1F), AddressTable.IP_R1);
        DHCPMessage response = server.handle(request, now).orElseThrow();
        assertTrue(response.isNak());
    }

    @Test
    void duplicateDiscoverIdempotent() {
        DHCPMessage offer1 = server.handle(DHCPMessage.discover(0x1, new MACAddress("N1")), now).orElseThrow();
        DHCPMessage offer2 = server.handle(DHCPMessage.discover(0x1, new MACAddress("N1")), now).orElseThrow();
        assertEquals(offer1.yourIP(), offer2.yourIP());
        // Pool only consumed once
        assertEquals(13, server.poolSize());
    }

    @Test
    void poolExhaustionReturnsEmpty() {
        // Drain all 14 addresses
        for (int i = 0; i < 14; i++) {
            MACAddress mac = new MACAddress("X" + Integer.toHexString(i));
            assertTrue(server.handle(DHCPMessage.discover(i, mac), now).isPresent());
        }
        assertEquals(0, server.poolSize());

        Optional<DHCPMessage> response = server.handle(DHCPMessage.discover(0xFF, new MACAddress("Y0")), now);
        assertTrue(response.isEmpty());
    }

    @Test
    void releaseReturnsAddressToPool() {
        DHCPMessage offer = server.handle(DHCPMessage.discover(0x1, new MACAddress("N1")), now).orElseThrow();
        server.handle(DHCPMessage.request(0x1, new MACAddress("N1"), offer.yourIP(), offer.serverIP()), now).orElseThrow();
        assertEquals(13, server.poolSize());
        assertEquals(1, server.leaseCount());

        server.handle(DHCPMessage.release(0x2, new MACAddress("N1"), offer.yourIP(), offer.serverIP()), now);
        assertEquals(14, server.poolSize());
        assertEquals(0, server.leaseCount());
        assertTrue(AddressTable.resolve(offer.yourIP()).isEmpty());
    }

    @Test
    void renewExtendsLease() {
        DHCPMessage offer = server.handle(DHCPMessage.discover(0x1, new MACAddress("N1")), now).orElseThrow();
        server.handle(DHCPMessage.request(0x1, new MACAddress("N1"), offer.yourIP(), offer.serverIP()), now).orElseThrow();

        long later = now + 30_000L; // half-way through 60s lease
        DHCPMessage renew = DHCPMessage.renew(0x3, new MACAddress("N1"), offer.yourIP(), offer.serverIP());
        DHCPMessage ack = server.handle(renew, later).orElseThrow();
        assertTrue(ack.isAck());

        // 90s after the original now (30s past original expiry) — lease should still be valid
        // because renew bumped expiry to later + 60s = now + 90s
        long evenLater = now + 89_000L;
        // Trigger expireLeases with a no-op call
        server.handle(DHCPMessage.discover(0x4, new MACAddress("N2")), evenLater);
        assertEquals(1, server.leaseCount(), "renewed lease should still be active");
        assertTrue(AddressTable.resolve(offer.yourIP()).isPresent());
    }

    @Test
    void renewForUnknownClientProducesNak() {
        DHCPMessage renew = DHCPMessage.renew(0x1, new MACAddress("N1"), new IPAddress(0x12), AddressTable.IP_R1);
        DHCPMessage response = server.handle(renew, now).orElseThrow();
        assertTrue(response.isNak());
    }

    @Test
    void expiredLeasesAreReclaimed() {
        DHCPMessage offer = server.handle(DHCPMessage.discover(0x1, new MACAddress("N1")), now).orElseThrow();
        server.handle(DHCPMessage.request(0x1, new MACAddress("N1"), offer.yourIP(), offer.serverIP()), now).orElseThrow();
        assertEquals(1, server.leaseCount());
        assertEquals(13, server.poolSize());

        // Trigger expiry by handling another message past the lease deadline
        long afterExpiry = now + 61_000L;
        server.handle(DHCPMessage.discover(0x2, new MACAddress("N2")), afterExpiry);

        // Original lease should be reclaimed (the new discover takes one address back out, so net pool: 13)
        assertFalse(server.leaseFor(new MACAddress("N1")).isPresent());
    }

    @Test
    void leaseForReturnsAssignedIP() {
        DHCPMessage offer = server.handle(DHCPMessage.discover(0x1, new MACAddress("N1")), now).orElseThrow();
        server.handle(DHCPMessage.request(0x1, new MACAddress("N1"), offer.yourIP(), offer.serverIP()), now).orElseThrow();

        Optional<IPAddress> leased = server.leaseFor(new MACAddress("N1"));
        assertTrue(leased.isPresent());
        assertEquals(offer.yourIP(), leased.get());
    }

    @Test
    void rediscoverWithExistingLeaseReturnsSameIP() {
        DHCPMessage offer = server.handle(DHCPMessage.discover(0x1, new MACAddress("N1")), now).orElseThrow();
        server.handle(DHCPMessage.request(0x1, new MACAddress("N1"), offer.yourIP(), offer.serverIP()), now).orElseThrow();

        // Client reboots and re-discovers
        DHCPMessage reOffer = server.handle(DHCPMessage.discover(0x42, new MACAddress("N1")), now).orElseThrow();
        assertEquals(offer.yourIP(), reOffer.yourIP());
    }

    @Test
    void serverIPMatchesGatewayForLAN() {
        assertEquals(AddressTable.IP_R1, server.serverIP());
        assertEquals(1, server.lanID());
    }

    @Test
    void discoverConsumesOneAddress() {
        int initial = server.poolSize();
        server.handle(DHCPMessage.discover(0x1, new MACAddress("N1")), now);
        assertEquals(initial - 1, server.poolSize());
    }
}
