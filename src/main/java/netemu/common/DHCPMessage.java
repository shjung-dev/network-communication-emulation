package netemu.common;

/**
 * DHCP Message Protocol
 * Format of Raw DHCP Message: [op:1][xid:2][clientMAC:2][yourIP:1][serverIP:1][leaseSecs:2][flags:1]
 *
 * Implements a compact 4-step DHCP exchange (DISCOVER → OFFER → REQUEST → ACK)
 * plus RELEASE/RENEW/NAK. Rides as the payload of an IPPacket with PROTOCOL_DHCP.
 *
 * The IP value 0x00 is reserved as "no address" (used by clients before they
 * have a lease) and 0xFF is the broadcast IP.
 */
public final class DHCPMessage {

    public static final int SIZE = 10;

    public static final byte OP_DISCOVER = 0x01;
    public static final byte OP_OFFER    = 0x02;
    public static final byte OP_REQUEST  = 0x03;
    public static final byte OP_ACK      = 0x04;
    public static final byte OP_NAK      = 0x05;
    public static final byte OP_RELEASE  = 0x06;
    public static final byte OP_RENEW    = 0x07;

    public static final IPAddress UNASSIGNED_IP = new IPAddress(0x00);
    public static final IPAddress BROADCAST_IP  = new IPAddress(0xFF);

    public static final byte FLAG_NONE      = 0x00;
    public static final byte FLAG_BROADCAST = 0x01;

    private final byte op;
    private final int xid;            // 16-bit transaction id
    private final MACAddress clientMAC;
    private final IPAddress yourIP;   // address being offered/assigned (or UNASSIGNED for DISCOVER)
    private final IPAddress serverIP; // DHCP server's IP (also serves as gateway hint)
    private final int leaseSecs;      // 16-bit lease duration
    private final byte flags;

    public DHCPMessage(byte op, int xid, MACAddress clientMAC, IPAddress yourIP,
                       IPAddress serverIP, int leaseSecs, byte flags) {
        if ((xid & 0xFFFF) != xid) {
            throw new IllegalArgumentException("xid must fit in 16 bits: " + xid);
        }
        if ((leaseSecs & 0xFFFF) != leaseSecs) {
            throw new IllegalArgumentException("leaseSecs must fit in 16 bits: " + leaseSecs);
        }
        this.op = op;
        this.xid = xid;
        this.clientMAC = clientMAC;
        this.yourIP = yourIP;
        this.serverIP = serverIP;
        this.leaseSecs = leaseSecs;
        this.flags = flags;
    }

    // Convenience constructors

    public static DHCPMessage discover(int xid, MACAddress clientMAC) {
        return new DHCPMessage(OP_DISCOVER, xid, clientMAC, UNASSIGNED_IP, UNASSIGNED_IP, 0, FLAG_BROADCAST);
    }

    public static DHCPMessage offer(int xid, MACAddress clientMAC, IPAddress yourIP, IPAddress serverIP, int leaseSecs) {
        return new DHCPMessage(OP_OFFER, xid, clientMAC, yourIP, serverIP, leaseSecs, FLAG_NONE);
    }

    public static DHCPMessage request(int xid, MACAddress clientMAC, IPAddress requestedIP, IPAddress serverIP) {
        return new DHCPMessage(OP_REQUEST, xid, clientMAC, requestedIP, serverIP, 0, FLAG_BROADCAST);
    }

    public static DHCPMessage ack(int xid, MACAddress clientMAC, IPAddress yourIP, IPAddress serverIP, int leaseSecs) {
        return new DHCPMessage(OP_ACK, xid, clientMAC, yourIP, serverIP, leaseSecs, FLAG_NONE);
    }

    public static DHCPMessage nak(int xid, MACAddress clientMAC, IPAddress serverIP) {
        return new DHCPMessage(OP_NAK, xid, clientMAC, UNASSIGNED_IP, serverIP, 0, FLAG_NONE);
    }

    public static DHCPMessage release(int xid, MACAddress clientMAC, IPAddress leasedIP, IPAddress serverIP) {
        return new DHCPMessage(OP_RELEASE, xid, clientMAC, leasedIP, serverIP, 0, FLAG_NONE);
    }

    public static DHCPMessage renew(int xid, MACAddress clientMAC, IPAddress leasedIP, IPAddress serverIP) {
        return new DHCPMessage(OP_RENEW, xid, clientMAC, leasedIP, serverIP, 0, FLAG_NONE);
    }

    // Encode to raw bytes
    public byte[] encode() {
        byte[] data = new byte[SIZE];
        data[0] = op;
        ByteUtil.putShort(data, 1, xid);
        clientMAC.writeTo(data, 3);
        data[5] = yourIP.toByte();
        data[6] = serverIP.toByte();
        ByteUtil.putShort(data, 7, leaseSecs);
        data[9] = flags;
        return data;
    }

    // Decode from raw bytes
    public static DHCPMessage decode(byte[] data) {
        if (data.length < SIZE) {
            throw new IllegalArgumentException("DHCP message too short: " + data.length);
        }
        byte op = data[0];
        int xid = ByteUtil.getShort(data, 1);
        MACAddress clientMAC = MACAddress.fromBytes(data, 3);
        IPAddress yourIP = IPAddress.fromByte(data, 5);
        IPAddress serverIP = IPAddress.fromByte(data, 6);
        int leaseSecs = ByteUtil.getShort(data, 7);
        byte flags = data[9];
        return new DHCPMessage(op, xid, clientMAC, yourIP, serverIP, leaseSecs, flags);
    }

    public byte op() { return op; }
    public int xid() { return xid; }
    public MACAddress clientMAC() { return clientMAC; }
    public IPAddress yourIP() { return yourIP; }
    public IPAddress serverIP() { return serverIP; }
    public int leaseSecs() { return leaseSecs; }
    public byte flags() { return flags; }

    public boolean isDiscover() { return op == OP_DISCOVER; }
    public boolean isOffer()    { return op == OP_OFFER; }
    public boolean isRequest()  { return op == OP_REQUEST; }
    public boolean isAck()      { return op == OP_ACK; }
    public boolean isNak()      { return op == OP_NAK; }
    public boolean isRelease()  { return op == OP_RELEASE; }
    public boolean isRenew()    { return op == OP_RENEW; }

    public String opName() {
        return switch (op) {
            case OP_DISCOVER -> "DISCOVER";
            case OP_OFFER    -> "OFFER";
            case OP_REQUEST  -> "REQUEST";
            case OP_ACK      -> "ACK";
            case OP_NAK      -> "NAK";
            case OP_RELEASE  -> "RELEASE";
            case OP_RENEW    -> "RENEW";
            default -> "OP" + (op & 0xFF);
        };
    }

    @Override
    public String toString() {
        return String.format("DHCP %s xid=0x%04x client=%s yourIP=%s serverIP=%s lease=%ds",
                opName(), xid, clientMAC, yourIP, serverIP, leaseSecs);
    }
}
