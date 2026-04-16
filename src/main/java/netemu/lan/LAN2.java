package netemu.lan;

import netemu.common.AddressTable;

import java.io.IOException;

public class LAN2 {
    public static void main(String[] args) throws IOException {
        new LAN(2, AddressTable.LAN2_PORT).start();
    }
}
