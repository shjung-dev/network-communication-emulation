package netemu.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TextMessageTest {

    @Test
    void plaintextEncodeDecodeRoundTrip() {
        TextMessage msg = TextMessage.plaintext("Hello World");
        byte[] encoded = msg.encode();
        TextMessage decoded = TextMessage.decode(encoded);

        assertFalse(decoded.isEncrypted());
        assertEquals("Hello World", decoded.text());
    }

    @Test
    void encryptedEncodeDecodeRoundTrip() {
        TextMessage msg = TextMessage.encrypted("Secret Data");
        byte[] encoded = msg.encode();
        TextMessage decoded = TextMessage.decode(encoded);

        assertTrue(decoded.isEncrypted());
        assertEquals("Secret Data", decoded.text());
    }

    @Test
    void encryptedDataIsObfuscatedOnWire() {
        TextMessage msg = TextMessage.encrypted("Hello");
        byte[] encoded = msg.encode();

        // The raw bytes on the wire should NOT contain the plaintext
        String raw = new String(encoded, TextMessage.HEADER_SIZE, encoded.length - TextMessage.HEADER_SIZE);
        assertNotEquals("Hello", raw);
    }

    @Test
    void decodeRawDoesNotDecrypt() {
        TextMessage msg = TextMessage.encrypted("Secret");
        byte[] encoded = msg.encode();
        TextMessage raw = TextMessage.decodeRaw(encoded);

        assertTrue(raw.isEncrypted());
        // The raw text should be the XOR-encrypted version, not the original
        assertNotEquals("Secret", raw.text());
    }

    @Test
    void plaintextDecodeRawSameAsDecode() {
        TextMessage msg = TextMessage.plaintext("Open Text");
        byte[] encoded = msg.encode();

        TextMessage decoded = TextMessage.decode(encoded);
        TextMessage raw = TextMessage.decodeRaw(encoded);

        assertEquals(decoded.text(), raw.text());
    }

    @Test
    void headerSizeIsTwo() {
        TextMessage msg = TextMessage.plaintext("AB");
        byte[] encoded = msg.encode();
        assertEquals(TextMessage.HEADER_SIZE + 2, encoded.length);
    }

    @Test
    void encryptedFlagByte() {
        assertEquals(TextMessage.PLAINTEXT, TextMessage.plaintext("x").encryptedFlag());
        assertEquals(TextMessage.ENCRYPTED, TextMessage.encrypted("x").encryptedFlag());
    }

    @Test
    void emptyTextMessage() {
        TextMessage msg = TextMessage.plaintext("");
        byte[] encoded = msg.encode();
        TextMessage decoded = TextMessage.decode(encoded);
        assertEquals("", decoded.text());
    }

    @Test
    void encryptedEmptyTextMessage() {
        TextMessage msg = TextMessage.encrypted("");
        byte[] encoded = msg.encode();
        TextMessage decoded = TextMessage.decode(encoded);
        assertEquals("", decoded.text());
    }

    @Test
    void maxLengthText() {
        String text = "A".repeat(TextMessage.MAX_TEXT_LENGTH);
        TextMessage msg = TextMessage.plaintext(text);
        byte[] encoded = msg.encode();
        TextMessage decoded = TextMessage.decode(encoded);
        assertEquals(text, decoded.text());
    }

    @Test
    void exceedsMaxLengthThrows() {
        String tooLong = "A".repeat(TextMessage.MAX_TEXT_LENGTH + 1);
        assertThrows(IllegalArgumentException.class, () -> TextMessage.plaintext(tooLong));
    }

    @Test
    void tooShortDataThrows() {
        byte[] tooShort = new byte[1];
        assertThrows(IllegalArgumentException.class, () -> TextMessage.decode(tooShort));
    }

    @Test
    void toStringContainsText() {
        TextMessage plain = TextMessage.plaintext("test");
        assertTrue(plain.toString().contains("PLAIN"));
        assertTrue(plain.toString().contains("test"));

        TextMessage enc = TextMessage.encrypted("secret");
        assertTrue(enc.toString().contains("ENCRYPTED"));
        assertTrue(enc.toString().contains("secret"));
    }

    @Test
    void fullStackWithIPPacketAndEthernetFrame() {
        // Text message inside IP inside Ethernet
        TextMessage msg = TextMessage.plaintext("Hello Node3");
        IPPacket ip = IPPacket.data(new IPAddress(0x12), new IPAddress(0x22), msg.encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N1"), new MACAddress("R1"), ip.encode());

        byte[] wire = frame.encode();

        EthernetFrame decodedFrame = EthernetFrame.decode(wire);
        IPPacket decodedIP = IPPacket.decode(decodedFrame.data());
        TextMessage decodedMsg = TextMessage.decode(decodedIP.data());

        assertEquals(IPPacket.PROTOCOL_DATA, decodedIP.protocol());
        assertEquals("Hello Node3", decodedMsg.text());
        assertFalse(decodedMsg.isEncrypted());
    }

    @Test
    void fullStackEncryptedMessage() {
        TextMessage msg = TextMessage.encrypted("Top Secret");
        IPPacket ip = IPPacket.data(new IPAddress(0x13), new IPAddress(0x32), msg.encode());
        EthernetFrame frame = new EthernetFrame(new MACAddress("N2"), new MACAddress("R1"), ip.encode());

        byte[] wire = frame.encode();

        EthernetFrame decodedFrame = EthernetFrame.decode(wire);
        IPPacket decodedIP = IPPacket.decode(decodedFrame.data());

        // Sniffing: decodeRaw should NOT reveal the plaintext
        TextMessage raw = TextMessage.decodeRaw(decodedIP.data());
        assertNotEquals("Top Secret", raw.text());

        // Legitimate receiver: decode should decrypt and reveal the plaintext
        TextMessage decrypted = TextMessage.decode(decodedIP.data());
        assertEquals("Top Secret", decrypted.text());
    }
}
