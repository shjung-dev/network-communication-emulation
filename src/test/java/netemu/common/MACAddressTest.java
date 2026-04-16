package netemu.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MACAddressTest {

    @Test
    void constructorAcceptsTwoCharString() {
        MACAddress mac = new MACAddress("N1");
        assertEquals("N1", mac.value());
    }

    @Test
    void constructorRejectsNull() {
        assertThrows(IllegalArgumentException.class, () -> new MACAddress(null));
    }

    @Test
    void constructorRejectsSingleChar() {
        assertThrows(IllegalArgumentException.class, () -> new MACAddress("A"));
    }

    @Test
    void constructorRejectsThreeChars() {
        assertThrows(IllegalArgumentException.class, () -> new MACAddress("ABC"));
    }

    @Test
    void toBytesReturnsTwoAsciiBytes() {
        MACAddress mac = new MACAddress("N1");
        byte[] bytes = mac.toBytes();
        assertEquals(2, bytes.length);
        assertEquals('N', (char) bytes[0]);
        assertEquals('1', (char) bytes[1]);
    }

    @Test
    void writeToPlacesBytesAtOffset() {
        MACAddress mac = new MACAddress("R2");
        byte[] buf = new byte[6];
        mac.writeTo(buf, 2);
        assertEquals('R', (char) buf[2]);
        assertEquals('2', (char) buf[3]);
    }

    @Test
    void fromBytesDecodesTwoAsciiChars() {
        byte[] data = {'X', 'N', '3', 'Y'};
        MACAddress mac = MACAddress.fromBytes(data, 1);
        assertEquals("N3", mac.value());
    }

    @Test
    void roundTripEncodeDecode() {
        MACAddress original = new MACAddress("R1");
        byte[] encoded = original.toBytes();
        MACAddress decoded = MACAddress.fromBytes(encoded, 0);
        assertEquals(original, decoded);
    }

    @Test
    void broadcastConstantIsFF() {
        assertEquals("FF", MACAddress.BROADCAST.value());
        assertTrue(MACAddress.BROADCAST.isBroadcast());
    }

    @Test
    void nonBroadcastReturnsFalse() {
        assertFalse(new MACAddress("N1").isBroadcast());
    }

    @Test
    void equalsAndHashCode() {
        MACAddress a = new MACAddress("N1");
        MACAddress b = new MACAddress("N1");
        MACAddress c = new MACAddress("N2");
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
    }

    @Test
    void toStringReturnsValue() {
        assertEquals("N4", new MACAddress("N4").toString());
    }
}
