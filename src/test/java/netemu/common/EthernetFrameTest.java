package netemu.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EthernetFrameTest {

    @Test
    void encodeProducesCorrectFormat() {
        MACAddress src = new MACAddress("N1");
        MACAddress dst = new MACAddress("R1");
        byte[] data = {0x01, 0x02, 0x03};
        EthernetFrame frame = new EthernetFrame(src, dst, data);

        byte[] encoded = frame.encode();
        assertEquals(EthernetFrame.HEADER_SIZE + 3, encoded.length);
        // Source MAC
        assertEquals('N', (char) encoded[0]);
        assertEquals('1', (char) encoded[1]);
        // Destination MAC
        assertEquals('R', (char) encoded[2]);
        assertEquals('1', (char) encoded[3]);
        // Data length
        assertEquals(3, encoded[4] & 0xFF);
        // Data
        assertEquals(0x01, encoded[5]);
        assertEquals(0x02, encoded[6]);
        assertEquals(0x03, encoded[7]);
    }

    @Test
    void decodeReconstructsFrame() {
        byte[] raw = {'N', '2', 'R', '2', 0x02, 0x0A, 0x0B};
        EthernetFrame frame = EthernetFrame.decode(raw);

        assertEquals("N2", frame.sourceMACAddress().value());
        assertEquals("R2", frame.destinationMACAddress().value());
        assertEquals(2, frame.dataLength());
        assertArrayEquals(new byte[]{0x0A, 0x0B}, frame.data());
    }

    @Test
    void encodeDecodeRoundTrip() {
        MACAddress src = new MACAddress("N3");
        MACAddress dst = new MACAddress("R2");
        byte[] data = "Hello".getBytes();
        EthernetFrame original = new EthernetFrame(src, dst, data);

        byte[] encoded = original.encode();
        EthernetFrame decoded = EthernetFrame.decode(encoded);

        assertEquals(original.sourceMACAddress(), decoded.sourceMACAddress());
        assertEquals(original.destinationMACAddress(), decoded.destinationMACAddress());
        assertArrayEquals(original.data(), decoded.data());
    }

    @Test
    void encodeDecodeWithEmptyData() {
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("N2"), new byte[0]);
        byte[] encoded = frame.encode();
        assertEquals(EthernetFrame.HEADER_SIZE, encoded.length);

        EthernetFrame decoded = EthernetFrame.decode(encoded);
        assertEquals(0, decoded.dataLength());
    }

    @Test
    void encodeDecodeWithMaxRoundTripData() {
        // 1-byte length field supports 0-255; 255 is the max that round-trips
        byte[] data = new byte[255];
        for (int i = 0; i < 255; i++) data[i] = (byte) i;
        EthernetFrame frame = new EthernetFrame(new MACAddress("N4"), new MACAddress("R3"), data);

        byte[] encoded = frame.encode();
        assertEquals(EthernetFrame.HEADER_SIZE + 255, encoded.length);

        EthernetFrame decoded = EthernetFrame.decode(encoded);
        assertArrayEquals(data, decoded.data());
    }

    @Test
    void constructorRejectsOversizeData() {
        byte[] tooLarge = new byte[257];
        assertThrows(IllegalArgumentException.class,
                () -> new EthernetFrame(new MACAddress("N1"), new MACAddress("N2"), tooLarge));
    }

    @Test
    void decodeRejectsTooShortFrame() {
        byte[] tooShort = new byte[4];
        assertThrows(IllegalArgumentException.class, () -> EthernetFrame.decode(tooShort));
    }

    @Test
    void dataLengthFieldIsUnsigned() {
        // Data length 200 should encode as unsigned byte
        byte[] data = new byte[200];
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("N2"), data);
        byte[] encoded = frame.encode();
        assertEquals(200, encoded[4] & 0xFF);

        EthernetFrame decoded = EthernetFrame.decode(encoded);
        assertEquals(200, decoded.dataLength());
    }

    @Test
    void toStringContainsAddresses() {
        EthernetFrame frame = new EthernetFrame(
                new MACAddress("N1"), new MACAddress("R1"), new byte[10]);
        String str = frame.toString();
        assertTrue(str.contains("N1"));
        assertTrue(str.contains("R1"));
        assertTrue(str.contains("10 bytes"));
    }

    @Test
    void encodeDecodeWithIPPacketPayload() {
        // Simulate real usage: IP packet inside Ethernet frame
        IPPacket ip = IPPacket.icmp(new IPAddress(0x12), new IPAddress(0x22),
                PingMessage.request(1).encode());
        byte[] ipBytes = ip.encode();

        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"), ipBytes);
        byte[] encoded = frame.encode();
        EthernetFrame decoded = EthernetFrame.decode(encoded);

        IPPacket decodedIP = IPPacket.decode(decoded.data());
        assertEquals(0x12, decodedIP.sourceIPAddress().value());
        assertEquals(0x22, decodedIP.destinationIPAddress().value());
        assertEquals(IPPacket.PROTOCOL_ICMP, decodedIP.protocol());
    }
}
