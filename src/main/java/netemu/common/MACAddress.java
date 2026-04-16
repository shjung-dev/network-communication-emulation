package netemu.common;

import java.util.Objects;

public class MACAddress {

    public static final MACAddress BROADCAST = new MACAddress("FF");

    private final String value;

    public MACAddress(String value) {
        if (value == null || value.length() != 2) {
            throw new IllegalArgumentException("MAC address must be exactly 2 characters: " + value);
        }
        this.value = value;
    }

    // Decodes a two-byte MAC field from packet data
    public static MACAddress fromBytes(byte[] data, int offset) {
        char c1 = (char) (data[offset] & 0xFF);
        char c2 = (char) (data[offset + 1] & 0xFF);
        return new MACAddress("" + c1 + c2);
    }

    // Encodes this address into its two-byte ASCII wire representation
    public byte[] toBytes() {
        return new byte[] { (byte) value.charAt(0), (byte) value.charAt(1) };
    }

    // Writes this two-byte address into dst starting at the given offset
    public void writeTo(byte[] dst, int offset) {
        dst[offset] = (byte) value.charAt(0);
        dst[offset + 1] = (byte) value.charAt(1);
    }

    // Returns the raw two-character address token
    public String value() { return value; }

    // Checks whether this MAC address is the broadcast address
    public boolean isBroadcast() {
        return "FF".equals(value);
    }

    // Compares two MACAddress objects
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MACAddress that)) return false;
        return value.equals(that.value);
    }

    // Returns a hash code based on the address token
    @Override
    public int hashCode() {
        return Objects.hash(value); 
    }

    // Returns this MAC address as a string
    @Override
    public String toString() {
        return value;
    }
    
}
