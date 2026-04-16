package netemu.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IPAddressTest {

    @Test
    void constructorAcceptsValidRange() {
        IPAddress ip = new IPAddress(0x12);
        assertEquals(0x12, ip.value());
    }

    @Test
    void constructorAcceptsZero() {
        assertEquals(0, new IPAddress(0x00).value());
    }

    @Test
    void constructorAcceptsMax() {
        assertEquals(0xFF, new IPAddress(0xFF).value());
    }

    @Test
    void constructorRejectsNegative() {
        assertThrows(IllegalArgumentException.class, () -> new IPAddress(-1));
    }

    @Test
    void constructorRejectsOverMax() {
        assertThrows(IllegalArgumentException.class, () -> new IPAddress(0x100));
    }

    @Test
    void parseHexWithPrefix() {
        IPAddress ip = IPAddress.parse("0x22");
        assertEquals(0x22, ip.value());
    }

    @Test
    void parseHexWithoutPrefix() {
        IPAddress ip = IPAddress.parse("32");
        assertEquals(0x32, ip.value());
    }

    @Test
    void parseHexUpperCasePrefix() {
        IPAddress ip = IPAddress.parse("0X13");
        assertEquals(0x13, ip.value());
    }

    @Test
    void toByteReturnsSingleByte() {
        IPAddress ip = new IPAddress(0xAB);
        assertEquals((byte) 0xAB, ip.toByte());
    }

    @Test
    void fromByteAtOffset() {
        byte[] data = {0x00, (byte) 0x32, 0x00};
        IPAddress ip = IPAddress.fromByte(data, 1);
        assertEquals(0x32, ip.value());
    }

    @Test
    void lanIDExtractsHighNibble() {
        assertEquals(1, new IPAddress(0x12).lanID());
        assertEquals(2, new IPAddress(0x22).lanID());
        assertEquals(3, new IPAddress(0x32).lanID());
        assertEquals(1, new IPAddress(0x11).lanID());
    }

    @Test
    void equalsAndHashCode() {
        IPAddress a = new IPAddress(0x12);
        IPAddress b = new IPAddress(0x12);
        IPAddress c = new IPAddress(0x13);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
    }

    @Test
    void toStringFormatsAsHex() {
        assertEquals("0x12", new IPAddress(0x12).toString());
        assertEquals("0x00", new IPAddress(0x00).toString());
        assertEquals("0xff", new IPAddress(0xFF).toString());
    }
}
