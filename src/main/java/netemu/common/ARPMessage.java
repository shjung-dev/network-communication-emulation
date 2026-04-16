package netemu.common;

/**
 * ARP-like control message carried inside IPPacket.PROTOCOL_ARP.
 *
 * Format:
 * [opcode:1][sender-ip:1][sender-mac:2][target-ip:1]
 */
public class ARPMessage {

    public static final int SIZE = 5;
    public static final byte REQUEST = 0x01;
    public static final byte REPLY = 0x02;

    private final byte opcode;
    private final IPAddress senderIP;
    private final MACAddress senderMAC;
    private final IPAddress targetIP;

    public ARPMessage(byte opcode, IPAddress senderIP, MACAddress senderMAC, IPAddress targetIP) {
        this.opcode = opcode;
        this.senderIP = senderIP;
        this.senderMAC = senderMAC;
        this.targetIP = targetIP;
    }

    public static ARPMessage request(IPAddress senderIP, MACAddress senderMAC, IPAddress targetIP) {
        return new ARPMessage(REQUEST, senderIP, senderMAC, targetIP);
    }

    public static ARPMessage reply(IPAddress senderIP, MACAddress senderMAC, IPAddress targetIP) {
        return new ARPMessage(REPLY, senderIP, senderMAC, targetIP);
    }

    public byte[] encode() {
        byte[] bytes = new byte[SIZE];
        bytes[0] = opcode;
        bytes[1] = senderIP.toByte();
        senderMAC.writeTo(bytes, 2);
        bytes[4] = targetIP.toByte();
        return bytes;
    }

    public static ARPMessage decode(byte[] data) {
        if (data.length < SIZE) {
            throw new IllegalArgumentException("ARP message too short: " + data.length);
        }
        byte opcode = data[0];
        IPAddress senderIP = IPAddress.fromByte(data, 1);
        MACAddress senderMAC = MACAddress.fromBytes(data, 2);
        IPAddress targetIP = IPAddress.fromByte(data, 4);
        return new ARPMessage(opcode, senderIP, senderMAC, targetIP);
    }

    public boolean isRequest() {
        return opcode == REQUEST;
    }

    public boolean isReply() {
        return opcode == REPLY;
    }

    public byte opcode() {
        return opcode;
    }

    public IPAddress senderIP() {
        return senderIP;
    }

    public MACAddress senderMAC() {
        return senderMAC;
    }

    public IPAddress targetIP() {
        return targetIP;
    }

    @Override
    public String toString() {
        String op = isRequest() ? "REQUEST" : (isReply() ? "REPLY" : String.valueOf(opcode & 0xFF));
        return String.format("ARP %s [%s is-at %s, target=%s]", op, senderIP, senderMAC, targetIP);
    }
}
