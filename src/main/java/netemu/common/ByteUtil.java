package netemu.common;

public final class ByteUtil {

    private ByteUtil() {}

    // Write a 2-byte big-endian unsigned value into {@code dst} at {@code offset}
    public static void putShort(byte[] dst, int offset, int value) {
        dst[offset]     = (byte) ((value >> 8) & 0xFF);
        dst[offset + 1] = (byte) (value & 0xFF);
    }

    // Read a 2-byte big-endian unsigned value from {@code src} at {@code offset} 
    public static int getShort(byte[] src, int offset) {
        return ((src[offset] & 0xFF) << 8) | (src[offset + 1] & 0xFF);
    }

    // Convert a hex string (with optional 0x prefix) to an int
    public static int parseHex(String s) {
        String clean = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
        return Integer.parseInt(clean, 16);
    }

    // Format an int as a hex string with 0x prefix
    public static String toHex(int value) {
        return "0x" + String.format("%02x", value & 0xFF);
    }

    // Copy bytes from src into a new array
    public static byte[] slice(byte[] src, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(src, offset, result, 0, length);
        return result;
    }
}
