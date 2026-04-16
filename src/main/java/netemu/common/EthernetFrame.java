package netemu.common;

/**
 * Ethernet Frame Configuration
 * Format of Raw Ethernet Frame: [<source-MAC-address>:2][<destination-MAC-address>:2][data-length:1][data:up to 256]
 */
public final class EthernetFrame {
    
    public static final int HEADER_SIZE = 5;
    public static final int MAX_DATA_LENGTH = 256;

    private final MACAddress sourceMACAddress;
    private final MACAddress destinationMACAddress;
    private final byte[] data;

    public EthernetFrame(MACAddress sourceMACAddress, MACAddress destinationMACAddress, byte[] data) {
        if (data.length > MAX_DATA_LENGTH) {
            throw new IllegalArgumentException("Data exceeds max length of " + MAX_DATA_LENGTH + ": " + data.length);
        }
        this.sourceMACAddress = sourceMACAddress;
        this.destinationMACAddress = destinationMACAddress;
        this.data = data;
    }

     // Encode Ethernet Frame into raw packet bytes (byte array)
    public byte[] encode() {
        byte[] frame = new byte[HEADER_SIZE + data.length];
        sourceMACAddress.writeTo(frame, 0);
        destinationMACAddress.writeTo(frame, 2);
        frame[4] = (byte) data.length;
        System.arraycopy(data, 0, frame, HEADER_SIZE, data.length);
        return frame;
    }

    // Decode raw packet bytes (byte array) into an Ethernet Frame
    public static EthernetFrame decode(byte[] frame) {
        if (frame.length < HEADER_SIZE) {
            throw new IllegalArgumentException("Frame too short to be valid: " + frame.length);
        }
        MACAddress sourceMACAddress = MACAddress.fromBytes(frame, 0);
        MACAddress destinationMACAddress = MACAddress.fromBytes(frame, 2);
        int dataLength = frame[4] & 0xFF;
        byte[] data = ByteUtil.slice(frame, HEADER_SIZE, dataLength);
        return new EthernetFrame(sourceMACAddress, destinationMACAddress, data);
    }

    public MACAddress sourceMACAddress() {
        return sourceMACAddress;
    }

    public MACAddress destinationMACAddress() {
        return destinationMACAddress;
    }

    public byte[] data() {
        return data;
    }

    public int dataLength() {
        return data.length;
    }

    @Override
    public String toString() {
        return String.format("Frame [%s -> %s | %d bytes]", sourceMACAddress, destinationMACAddress, data.length);
    }
}
