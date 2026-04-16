package netemu.common;


/**
 * Ping (ICMP echo) Configuration
 * Format of Raw Ping Message: [type:1][sequence-number:1][timestamp:8]
 */
public class PingMessage {
    
    public static final int SIZE = 10;
    public static final byte ECHO_REPLY = 0x00;
    public static final byte ECHO_REQUEST = 0x08;

    private final byte type;
    private final int sequence;
    private final long timestamp;

    public PingMessage(byte type, int sequence, long timestamp) {
        this.type = type;
        this.sequence = sequence;
        this.timestamp = timestamp;
    }

    // Create an echo request with the current time
    public static PingMessage request(int sequence) {
        return new PingMessage(ECHO_REQUEST, sequence, System.currentTimeMillis());
    }

    // Create a reply from an incoming request (preserves sequence and timestamp)
    public PingMessage toReply() {
        return new PingMessage(ECHO_REPLY, sequence, timestamp);
    }

    // Encode Ping Message into raw packet bytes (10 bytes)
    public byte[] encode() {
        byte[] data = new byte[SIZE];
        data[0] = type;
        data[1] = (byte) sequence;
        for (int i = 0; i < 8; i++) {
            data[2 + i] = (byte) ((timestamp >> (56 - i * 8)) & 0xFF);
        }
        return data;
    }

    // Decode raw message bytes (byte array) into a Ping Message
    public static PingMessage decode(byte[] data) {
        if (data.length < SIZE) {
            throw new IllegalArgumentException("Ping message too short: " + data.length);
        }
        byte type = data[0];
        int sequence = data[1] & 0xFF;
        long timestamp = 0;
        for (int i = 0; i < 8; i++) {
            timestamp |= ((long)(data[2 + i] & 0xFF)) << (56 - i * 8);
        }
        return new PingMessage(type, sequence , timestamp);
    }

    // Round-trip time in ms from the embedded timestamp to now
    public long RTT() {
        return System.currentTimeMillis() - timestamp;
    }

    public byte type() {
        return type;
    }

    public int sequence() {
        return sequence;
    }

    public long timestamp() {
        return timestamp;
    }

    public boolean isRequest() {
        return type == ECHO_REQUEST;
    }

    public boolean isReply() {
        return type == ECHO_REPLY;
    }

    @Override
    public String toString() {
        return String.format("Ping %s seq=%d", isRequest() ? "REQUEST" : "REPLY", sequence);
    }
}
