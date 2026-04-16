package netemu.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IPPacketTest {

    @Test
    void encodeProducesCorrectFormat() {
        IPAddress src = new IPAddress(0x12);
        IPAddress dst = new IPAddress(0x22);
        byte[] data = {0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        IPPacket packet = new IPPacket(src, dst, IPPacket.PROTOCOL_ICMP, data);

        byte[] encoded = packet.encode();
        assertEquals(IPPacket.HEADER_SIZE + data.length, encoded.length);
        assertEquals(0x12, encoded[0] & 0xFF); // source IP
        assertEquals(0x22, encoded[1] & 0xFF); // destination IP
        assertEquals(0x01, encoded[2] & 0xFF); // protocol (ICMP)
        assertEquals(data.length, encoded[3] & 0xFF); // data length
    }

    @Test
    void decodeReconstructsPacket() {
        byte[] raw = {0x12, 0x22, 0x01, 0x03, 0x41, 0x42, 0x43};
        IPPacket packet = IPPacket.decode(raw);

        assertEquals(0x12, packet.sourceIPAddress().value());
        assertEquals(0x22, packet.destinationIPAddress().value());
        assertEquals(0x01, packet.protocol());
        assertEquals(3, packet.dataLength());
        assertArrayEquals(new byte[]{0x41, 0x42, 0x43}, packet.data());
    }

    @Test
    void encodeDecodeRoundTrip() {
        IPPacket original = new IPPacket(
                new IPAddress(0x13), new IPAddress(0x32),
                IPPacket.PROTOCOL_ICMP, "TEST".getBytes());

        byte[] encoded = original.encode();
        IPPacket decoded = IPPacket.decode(encoded);

        assertEquals(original.sourceIPAddress(), decoded.sourceIPAddress());
        assertEquals(original.destinationIPAddress(), decoded.destinationIPAddress());
        assertEquals(original.protocol(), decoded.protocol());
        assertArrayEquals(original.data(), decoded.data());
    }

    @Test
    void icmpFactoryMethodSetsProtocol() {
        IPPacket packet = IPPacket.icmp(
                new IPAddress(0x12), new IPAddress(0x22), new byte[]{1, 2, 3});
        assertEquals(IPPacket.PROTOCOL_ICMP, packet.protocol());
    }

    @Test
    void encodeDecodeWithEmptyData() {
        IPPacket packet = new IPPacket(
                new IPAddress(0x12), new IPAddress(0x13),
                (byte) 0, new byte[0]);

        byte[] encoded = packet.encode();
        assertEquals(IPPacket.HEADER_SIZE, encoded.length);

        IPPacket decoded = IPPacket.decode(encoded);
        assertEquals(0, decoded.dataLength());
    }

    @Test
    void encodeDecodeWithMaxRoundTripData() {
        // 1-byte length field supports 0-255; 255 is the max that round-trips
        byte[] data = new byte[255];
        for (int i = 0; i < 255; i++) data[i] = (byte) i;
        IPPacket packet = new IPPacket(
                new IPAddress(0x11), new IPAddress(0x31),
                IPPacket.PROTOCOL_ICMP, data);

        byte[] encoded = packet.encode();
        IPPacket decoded = IPPacket.decode(encoded);
        assertArrayEquals(data, decoded.data());
    }

    @Test
    void constructorRejectsOversizeData() {
        byte[] tooLarge = new byte[257];
        assertThrows(IllegalArgumentException.class,
                () -> new IPPacket(new IPAddress(0x12), new IPAddress(0x22), (byte) 0, tooLarge));
    }

    @Test
    void decodeRejectsTooShortPacket() {
        byte[] tooShort = new byte[3];
        assertThrows(IllegalArgumentException.class, () -> IPPacket.decode(tooShort));
    }

    @Test
    void dataLengthFieldIsUnsigned() {
        byte[] data = new byte[200];
        IPPacket packet = new IPPacket(
                new IPAddress(0x12), new IPAddress(0x22), (byte) 0, data);
        byte[] encoded = packet.encode();
        assertEquals(200, encoded[3] & 0xFF);

        IPPacket decoded = IPPacket.decode(encoded);
        assertEquals(200, decoded.dataLength());
    }

    @Test
    void protocolICMPConstantIsOne() {
        assertEquals(0x01, IPPacket.PROTOCOL_ICMP);
    }

    @Test
    void protocolDATAConstantIsTwo() {
        assertEquals(0x02, IPPacket.PROTOCOL_DATA);
    }

    @Test
    void dataFactoryMethodSetsProtocol() {
        IPPacket packet = IPPacket.data(
                new IPAddress(0x12), new IPAddress(0x22), new byte[]{1, 2, 3});
        assertEquals(IPPacket.PROTOCOL_DATA, packet.protocol());
    }

    @Test
    void toStringContainsAddresses() {
        IPPacket packet = IPPacket.icmp(new IPAddress(0x12), new IPAddress(0x22), new byte[5]);
        String str = packet.toString();
        assertTrue(str.contains("0x12"));
        assertTrue(str.contains("0x22"));
        assertTrue(str.contains("ICMP"));
    }

    @Test
    void toStringShowsDATAForDataProtocol() {
        IPPacket packet = IPPacket.data(new IPAddress(0x12), new IPAddress(0x22), new byte[5]);
        String str = packet.toString();
        assertTrue(str.contains("DATA"));
    }

    @Test
    void fullStackEncodeDecode() {
        // Ping inside IP inside Ethernet
        PingMessage ping = PingMessage.request(1);
        IPPacket ip = IPPacket.icmp(new IPAddress(0x12), new IPAddress(0x32), ping.encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"), ip.encode());

        byte[] wire = frame.encode();

        EthernetFrame decodedFrame = EthernetFrame.decode(wire);
        IPPacket decodedIP = IPPacket.decode(decodedFrame.data());
        PingMessage decodedPing = PingMessage.decode(decodedIP.data());

        assertEquals(0x12, decodedIP.sourceIPAddress().value());
        assertEquals(0x32, decodedIP.destinationIPAddress().value());
        assertTrue(decodedPing.isRequest());
        assertEquals(1, decodedPing.sequence());
    }
}
