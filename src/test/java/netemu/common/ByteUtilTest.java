package netemu.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ByteUtilTest {

    @Test
    void putShortWritesBigEndian() {
        byte[] buf = new byte[4];
        ByteUtil.putShort(buf, 1, 0x1234);
        assertEquals(0x12, buf[1] & 0xFF);
        assertEquals(0x34, buf[2] & 0xFF);
    }

    @Test
    void getShortReadsBigEndian() {
        byte[] buf = {0x00, 0x12, 0x34, 0x00};
        assertEquals(0x1234, ByteUtil.getShort(buf, 1));
    }

    @Test
    void putGetShortRoundTrip() {
        byte[] buf = new byte[2];
        ByteUtil.putShort(buf, 0, 0xABCD);
        assertEquals(0xABCD, ByteUtil.getShort(buf, 0));
    }

    @Test
    void parseHexWithPrefix() {
        assertEquals(0xFF, ByteUtil.parseHex("0xFF"));
        assertEquals(0x12, ByteUtil.parseHex("0x12"));
    }

    @Test
    void parseHexWithoutPrefix() {
        assertEquals(0x32, ByteUtil.parseHex("32"));
        assertEquals(0xAB, ByteUtil.parseHex("AB"));
    }

    @Test
    void parseHexUpperCasePrefix() {
        assertEquals(0x22, ByteUtil.parseHex("0X22"));
    }

    @Test
    void toHexFormatsWithPrefix() {
        assertEquals("0x12", ByteUtil.toHex(0x12));
        assertEquals("0x00", ByteUtil.toHex(0x00));
        assertEquals("0xff", ByteUtil.toHex(0xFF));
    }

    @Test
    void sliceCopiesSubArray() {
        byte[] src = {1, 2, 3, 4, 5};
        byte[] result = ByteUtil.slice(src, 1, 3);
        assertArrayEquals(new byte[]{2, 3, 4}, result);
    }

    @Test
    void sliceFromStart() {
        byte[] src = {10, 20, 30};
        byte[] result = ByteUtil.slice(src, 0, 2);
        assertArrayEquals(new byte[]{10, 20}, result);
    }

    @Test
    void sliceZeroLength() {
        byte[] src = {1, 2, 3};
        byte[] result = ByteUtil.slice(src, 1, 0);
        assertEquals(0, result.length);
    }

    @Test
    void sliceDoesNotModifySource() {
        byte[] src = {1, 2, 3};
        byte[] result = ByteUtil.slice(src, 0, 3);
        result[0] = 99;
        assertEquals(1, src[0]);
    }
}
