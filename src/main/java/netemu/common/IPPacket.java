package netemu.common;

/**
 * IP Packet Configuration
 * Format of Raw IP Packet: [<source-IP-address>:1][<destination-IP-address>:1][protocol:1][data-length:1][data:up to 256]
 */

public class IPPacket {
    
    public static final int HEADER_SIZE = 4;
    public static final int MAX_DATA_LENGTH = 256;
    public static final byte PROTOCOL_ICMP = 0x01;
    public static final byte PROTOCOL_DATA = 0x02;
    public static final byte PROTOCOL_DHCP = 0x03;
    public static final byte PROTOCOL_ARP = 0x04;

    private final byte[] data;
    private final byte protocol;
    private final IPAddress sourceIPAddress;
    private final IPAddress destinationIPAddress;

    public IPPacket(IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte protocol, byte[] data) {
        if (data.length > MAX_DATA_LENGTH) {
            throw new IllegalArgumentException("Data exceeds max length of " + MAX_DATA_LENGTH + ": " + data.length);
        }
        this.data = data;
        this.protocol = protocol;
        this.sourceIPAddress = sourceIPAddress;
        this.destinationIPAddress = destinationIPAddress;
    }

    // Create an ICMP/ping packet
    public static IPPacket icmp(IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte[] pingData) {
        return new IPPacket(sourceIPAddress, destinationIPAddress, PROTOCOL_ICMP, pingData);
    }

    // Create a data/text packet
    public static IPPacket data(IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte[] messageData) {
        return new IPPacket(sourceIPAddress, destinationIPAddress, PROTOCOL_DATA, messageData);
    }

    // Create a DHCP packet
    public static IPPacket dhcp(IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte[] dhcpData) {
        return new IPPacket(sourceIPAddress, destinationIPAddress, PROTOCOL_DHCP, dhcpData);
    }

    // Create an ARP control packet
    public static IPPacket arp(IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte[] arpData) {
        return new IPPacket(sourceIPAddress, destinationIPAddress, PROTOCOL_ARP, arpData);
    }

    // Encode IP Packet into raw packet bytes (byte array)
    public byte[] encode() {
        byte[] packet = new byte[HEADER_SIZE + data.length];
        packet[0] = sourceIPAddress.toByte();
        packet[1] = destinationIPAddress.toByte();
        packet[2] = protocol;
        packet[3] = (byte) data.length;
        System.arraycopy(data, 0, packet, HEADER_SIZE, data.length);
        return packet;
    }

    // Decode raw packet bytes (byte array) into an IP Packet
    public static IPPacket decode(byte[] packet) {
        if (packet.length < HEADER_SIZE) {
            throw new IllegalArgumentException("Packet too short to be valid (minimum " + HEADER_SIZE + " bytes): " + packet.length);
        }
        IPAddress sourceIPAddress = IPAddress.fromByte(packet, 0);
        IPAddress destinationIPAddress = IPAddress.fromByte(packet, 1);
        byte protocol = packet[2];
        int dataLength = packet[3] & 0xFF;
        byte[] data = ByteUtil.slice(packet, HEADER_SIZE, dataLength);
        return new IPPacket(sourceIPAddress, destinationIPAddress, protocol, data);
    }

    public IPAddress sourceIPAddress() {
        return sourceIPAddress;
    }

    public IPAddress destinationIPAddress() {
        return destinationIPAddress;
    }

    public byte protocol() {
        return protocol;
    }

    public byte[] data() {
        return data;
    }

    public int dataLength() {
        return data.length;
    }

    @Override
    public String toString() {
        String protoName = switch (protocol) {
            case PROTOCOL_ICMP -> "ICMP";
            case PROTOCOL_DATA -> "DATA";
            case PROTOCOL_DHCP -> "DHCP";
            case PROTOCOL_ARP -> "ARP";
            default -> String.valueOf(protocol & 0xFF);
        };
        return String.format("Packet [%s -> %s | %s | %d bytes]", sourceIPAddress, destinationIPAddress, protoName, data.length);
    }
}