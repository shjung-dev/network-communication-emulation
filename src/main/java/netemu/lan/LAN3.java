package netemu.lan;

import netemu.common.AddressTable;

import java.io.IOException;

public class LAN3 {
    public static void main(String[] args) throws IOException {
        new LAN(3, AddressTable.LAN3_PORT).start();
    }
}
