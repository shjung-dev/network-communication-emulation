package netemu.common;

import java.util.Objects;

public final class IPAddress {
    
    private final int value; 

    public IPAddress(int value) {
        if (value < 0 || value > 0xFF) {
            throw new IllegalArgumentException("IP Address must be between: 0x00-0xFF: " + value);
        }
        this.value = value;
    }

    // Parses an IP Address from a hex string 
    public static IPAddress parse(String hex) {
        return new IPAddress(ByteUtil.parseHex(hex));
    }

    // Builds an IP Address from one byte in a packet at the given offset
    public static IPAddress fromByte(byte[] data, int offset) {
        return new IPAddress(data[offset] & 0xFF);
    }

    // Returns the numeric IP Address value as an integer
    public int value() { return value; }

    // Returns the numeric IP Address value as a single byte
    public byte toByte() { return (byte) value; }

    // Extracts the LAN identifier from IP Address
    public int lanID() {
        return (value >> 4) & 0X0F;
    }

    // Compares two IP Address objects 
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof IPAddress that)) return false;
        return value == that.value;
    }

    // Returns a hash code based on the numeric address value
    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    // Formats this IP Address as a hexadecimal string
    @Override
    public String toString() {
        return ByteUtil.toHex(value);
    }
}
