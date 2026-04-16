package netemu.lan;

import netemu.common.AddressTable;

import java.io.IOException;

public class LAN1 {
    public static void main(String[] args) throws IOException {
        new LAN(1, AddressTable.LAN1_PORT).start();
    }
}
