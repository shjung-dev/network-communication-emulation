package netemu.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DHCPMessageTest {

    @Test
    void encodeProducesFixedSize() {
        DHCPMessage msg = DHCPMessage.discover(0x1234, new MACAddress("N1"));
        assertEquals(DHCPMessage.SIZE, msg.encode().length);
    }

    @Test
    void discoverRoundTrip() {
        DHCPMessage original = DHCPMessage.discover(0x1234, new MACAddress("N1"));
        DHCPMessage decoded = DHCPMessage.decode(original.encode());
        assertTrue(decoded.isDiscover());
        assertEquals(0x1234, decoded.xid());
        assertEquals("N1", decoded.clientMAC().value());
        assertEquals(0x00, decoded.yourIP().value());
        assertEquals(0x00, decoded.serverIP().value());
        assertEquals(0, decoded.leaseSecs());
    }

    @Test
    void offerRoundTrip() {
        DHCPMessage original = DHCPMessage.offer(0xABCD, new MACAddress("N2"),
                new IPAddress(0x13), new IPAddress(0x11), 60);
        DHCPMessage decoded = DHCPMessage.decode(original.encode());
        assertTrue(decoded.isOffer());
        assertEquals(0xABCD, decoded.xid());
        assertEquals("N2", decoded.clientMAC().value());
        assertEquals(0x13, decoded.yourIP().value());
        assertEquals(0x11, decoded.serverIP().value());
        assertEquals(60, decoded.leaseSecs());
    }

    @Test
    void requestRoundTrip() {
        DHCPMessage msg = DHCPMessage.request(0x0001, new MACAddress("N3"),
                new IPAddress(0x22), new IPAddress(0x21));
        DHCPMessage decoded = DHCPMessage.decode(msg.encode());
        assertTrue(decoded.isRequest());
        assertEquals(0x22, decoded.yourIP().value());
        assertEquals(0x21, decoded.serverIP().value());
    }

    @Test
    void ackRoundTrip() {
        DHCPMessage msg = DHCPMessage.ack(0x4242, new MACAddress("N4"),
                new IPAddress(0x32), new IPAddress(0x31), 120);
        DHCPMessage decoded = DHCPMessage.decode(msg.encode());
        assertTrue(decoded.isAck());
        assertEquals(120, decoded.leaseSecs());
    }

    @Test
    void nakRoundTrip() {
        DHCPMessage msg = DHCPMessage.nak(0x9999, new MACAddress("N1"), new IPAddress(0x11));
        DHCPMessage decoded = DHCPMessage.decode(msg.encode());
        assertTrue(decoded.isNak());
        assertEquals(0x00, decoded.yourIP().value());
        assertEquals(0x11, decoded.serverIP().value());
    }

    @Test
    void releaseRoundTrip() {
        DHCPMessage msg = DHCPMessage.release(0x0042, new MACAddress("N2"),
                new IPAddress(0x13), new IPAddress(0x11));
        DHCPMessage decoded = DHCPMessage.decode(msg.encode());
        assertTrue(decoded.isRelease());
        assertEquals(0x13, decoded.yourIP().value());
    }

    @Test
    void renewRoundTrip() {
        DHCPMessage msg = DHCPMessage.renew(0x0099, new MACAddress("N4"),
                new IPAddress(0x32), new IPAddress(0x31));
        DHCPMessage decoded = DHCPMessage.decode(msg.encode());
        assertTrue(decoded.isRenew());
    }

    @Test
    void decodeRejectsTooShortMessage() {
        assertThrows(IllegalArgumentException.class,
                () -> DHCPMessage.decode(new byte[5]));
    }

    @Test
    void xidMustFitIn16Bits() {
        assertThrows(IllegalArgumentException.class,
                () -> new DHCPMessage(DHCPMessage.OP_DISCOVER, 0x10000, new MACAddress("N1"),
                        DHCPMessage.UNASSIGNED_IP, DHCPMessage.UNASSIGNED_IP, 0, DHCPMessage.FLAG_NONE));
    }

    @Test
    void leaseSecsMustFitIn16Bits() {
        assertThrows(IllegalArgumentException.class,
                () -> new DHCPMessage(DHCPMessage.OP_ACK, 0x1, new MACAddress("N1"),
                        new IPAddress(0x12), new IPAddress(0x11), 0x10000, DHCPMessage.FLAG_NONE));
    }

    @Test
    void discoverHasBroadcastFlag() {
        DHCPMessage msg = DHCPMessage.discover(0x0001, new MACAddress("N1"));
        assertEquals(DHCPMessage.FLAG_BROADCAST, msg.flags());
    }

    @Test
    void opNameForKnownOps() {
        assertEquals("DISCOVER", DHCPMessage.discover(1, new MACAddress("N1")).opName());
        assertEquals("OFFER", DHCPMessage.offer(1, new MACAddress("N1"), new IPAddress(0x12), new IPAddress(0x11), 60).opName());
        assertEquals("REQUEST", DHCPMessage.request(1, new MACAddress("N1"), new IPAddress(0x12), new IPAddress(0x11)).opName());
        assertEquals("ACK", DHCPMessage.ack(1, new MACAddress("N1"), new IPAddress(0x12), new IPAddress(0x11), 60).opName());
        assertEquals("NAK", DHCPMessage.nak(1, new MACAddress("N1"), new IPAddress(0x11)).opName());
        assertEquals("RELEASE", DHCPMessage.release(1, new MACAddress("N1"), new IPAddress(0x12), new IPAddress(0x11)).opName());
        assertEquals("RENEW", DHCPMessage.renew(1, new MACAddress("N1"), new IPAddress(0x12), new IPAddress(0x11)).opName());
    }

    @Test
    void toStringContainsOpAndAddresses() {
        DHCPMessage msg = DHCPMessage.offer(0x1234, new MACAddress("N2"),
                new IPAddress(0x13), new IPAddress(0x11), 60);
        String str = msg.toString();
        assertTrue(str.contains("OFFER"));
        assertTrue(str.contains("N2"));
        assertTrue(str.contains("0x13"));
        assertTrue(str.contains("0x11"));
    }

    @Test
    void canBeCarriedInsideIPPacket() {
        DHCPMessage dhcp = DHCPMessage.discover(0x4242, new MACAddress("N1"));
        IPPacket packet = IPPacket.dhcp(DHCPMessage.UNASSIGNED_IP, DHCPMessage.BROADCAST_IP, dhcp.encode());

        byte[] wire = packet.encode();
        IPPacket decodedPacket = IPPacket.decode(wire);
        assertEquals(IPPacket.PROTOCOL_DHCP, decodedPacket.protocol());

        DHCPMessage decodedDhcp = DHCPMessage.decode(decodedPacket.data());
        assertTrue(decodedDhcp.isDiscover());
        assertEquals(0x4242, decodedDhcp.xid());
    }

    @Test
    void protocolDhcpConstantIsThree() {
        assertEquals(0x03, IPPacket.PROTOCOL_DHCP);
    }

    @Test
    void ipPacketToStringShowsDHCP() {
        DHCPMessage dhcp = DHCPMessage.discover(0x1, new MACAddress("N1"));
        IPPacket packet = IPPacket.dhcp(DHCPMessage.UNASSIGNED_IP, DHCPMessage.BROADCAST_IP, dhcp.encode());
        assertTrue(packet.toString().contains("DHCP"));
    }
}
