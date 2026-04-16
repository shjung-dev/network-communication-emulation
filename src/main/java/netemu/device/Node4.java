package netemu.device;

import netemu.common.Ansi;
import netemu.common.AddressTable;

import java.io.IOException;

/**
 * Node 4
 *  - Role: Normal device in LAN3
 *  - MAC Address: N4
 *  - IP Address: 0x32
 *  - Port Number: 6004
 *  - LAN ID: 3
 */
public class Node4 extends Node {

    public Node4() {
        super("Node4", new NetworkInterface(AddressTable.MAC_N4, AddressTable.IP_N4, 3, AddressTable.NODE4_PORT, AddressTable.LAN3_PORT), Ansi.GREEN);
    }

    @Override
    protected String logColor() {
        return Ansi.GREEN;
    }

    public static void main(String[] args) throws IOException {
        boolean useStatic = args.length > 0 && "--static".equalsIgnoreCase(args[0]);
        new Node4().start(!useStatic);
    }
}
