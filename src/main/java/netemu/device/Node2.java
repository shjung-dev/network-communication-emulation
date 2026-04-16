package netemu.device;

import netemu.common.AddressTable;
import netemu.common.Ansi;

import java.io.IOException;

/**
 * Node 2
 *  - Role: Normal device in LAN1
 *  - MAC Address: N2
 *  - IP Address: 0x13
 *  - Port Number: 6002
 *  - LAN ID: 1
 */
public class Node2 extends Node {

    public Node2() {
        super("Node2", new NetworkInterface(AddressTable.MAC_N2, AddressTable.IP_N2,1, AddressTable.NODE2_PORT, AddressTable.LAN1_PORT), Ansi.GREEN);
    }

    @Override
    protected String logColor() {
        return Ansi.GREEN;
    }

    public static void main(String[] args) throws IOException {
        boolean useStatic = args.length > 0 && "--static".equalsIgnoreCase(args[0]);
        new Node2().start(!useStatic);
    }
}
