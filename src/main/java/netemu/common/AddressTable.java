package netemu.common;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public final class AddressTable {

    private AddressTable() {}

    // Port Numbers - LAN EMULATORS
    public static final int LAN1_PORT = 5001;
    public static final int LAN2_PORT = 5002;
    public static final int LAN3_PORT = 5003;

    // Port Numbers - NODES
    public static final int NODE1_PORT = 6001;
    public static final int NODE2_PORT = 6002;
    public static final int NODE3_PORT = 6003;
    public static final int NODE4_PORT = 6004;

    // Port Numbers - ROUTERS
    public static final int ROUTER1_PORT = 6011;
    public static final int ROUTER2_PORT = 6012;
    public static final int ROUTER3_PORT = 6013;

    // MAC Addresses - NODES
    public static final MACAddress MAC_N1 = new MACAddress("N1");
    public static final MACAddress MAC_N2 = new MACAddress("N2");
    public static final MACAddress MAC_N3 = new MACAddress("N3");
    public static final MACAddress MAC_N4 = new MACAddress("N4");

    // MAC Addresses - ROUTERS
    public static final MACAddress MAC_R1 = new MACAddress("R1");
    public static final MACAddress MAC_R2 = new MACAddress("R2");
    public static final MACAddress MAC_R3 = new MACAddress("R3");

    // Default IP Addresses - NODES (used for static mode and as legacy defaults)
    public static final IPAddress IP_N1 = new IPAddress(0x12);
    public static final IPAddress IP_N2 = new IPAddress(0x13);
    public static final IPAddress IP_N3 = new IPAddress(0x22);
    public static final IPAddress IP_N4 = new IPAddress(0x32);

    // IP Addresses - ROUTERS (infrastructure, always reserved)
    public static final IPAddress IP_R1 = new IPAddress(0x11);
    public static final IPAddress IP_R2 = new IPAddress(0x21);
    public static final IPAddress IP_R3 = new IPAddress(0x31);

    // Maps LAN ID to LAN Emulator Port Number
    private static final Map<Integer, Integer> LAN_PORTS_MAP = Map.of(
        1, LAN1_PORT,
        2, LAN2_PORT,
        3, LAN3_PORT
    );

    // Spec-mandated MAC -> IP bindings. DHCP server consults this to ensure each
    // node always receives its topology IP regardless of DISCOVER ordering.
    private static final Map<MACAddress, IPAddress> PREFERRED_IP = Map.of(
        MAC_N1, IP_N1,
        MAC_N2, IP_N2,
        MAC_N3, IP_N3,
        MAC_N4, IP_N4
    );

    public static Optional<IPAddress> preferredIPFor(MACAddress mac) {
        return Optional.ofNullable(PREFERRED_IP.get(mac));
    }

    // Mutable IP -> MAC table. Routers are seeded statically; nodes are populated either
    // by the legacy seed below (static mode) or by DHCP at runtime.
    private static final Map<IPAddress, MACAddress> IP_TO_MAC = new ConcurrentHashMap<>();

    // Mutable IP -> LAN ID table. Same seeding rules as IP_TO_MAC.
    private static final Map<IPAddress, Integer> IP_TO_LAN = new ConcurrentHashMap<>();

    static {
        // Routers always present — they are infrastructure, never DHCP-assigned
        bind(IP_R1, MAC_R1, 1);
        bind(IP_R2, MAC_R2, 2);
        bind(IP_R3, MAC_R3, 3);

        // Default node bindings for static mode. DHCP clients will rebind these
        // to whatever address they actually receive in their lease.
        bind(IP_N1, MAC_N1, 1);
        bind(IP_N2, MAC_N2, 1);
        bind(IP_N3, MAC_N3, 2);
        bind(IP_N4, MAC_N4, 3);
    }

    // Get the LAN emulator port number for a LAN ID
    public static int getLANPortNumber(int lanID) {
        Integer port = LAN_PORTS_MAP.get(lanID);
        if (port == null) throw new IllegalArgumentException("Unknown LAN ID: " + lanID);
        return port;
    }

    // Resolve an IP Address to a MAC Address.
    // Returns Optional.empty() if no binding is currently known (e.g., a DHCP client
    // has not yet been assigned an address).
    public static Optional<MACAddress> resolve(IPAddress ipAddress) {
        return Optional.ofNullable(IP_TO_MAC.get(ipAddress));
    }

    // Get which LAN the IP Address belongs to
    public static int getLANForIP(IPAddress ipAddress) {
        Integer lan = IP_TO_LAN.get(ipAddress);
        if (lan == null) throw new IllegalArgumentException("Unknown IP: " + ipAddress);
        return lan;
    }

    // Determine the router's MAC Address for a destination IP Address when routing cross-LAN
    public static MACAddress getRouterMACAddressForLAN(int lanID) {
        return switch (lanID) {
            case 1 -> MAC_R1;
            case 2 -> MAC_R2;
            case 3 -> MAC_R3;
            default -> throw new IllegalArgumentException("Unknown LAN ID: " + lanID);
        };
    }

    // Get the router's IP Address on a given LAN
    public static IPAddress getRouterIPAddressForLAN(int lanID) {
        return switch (lanID) {
            case 1 -> IP_R1;
            case 2 -> IP_R2;
            case 3 -> IP_R3;
            default -> throw new IllegalArgumentException("Unknown LAN ID: " + lanID);
        };
    }

    // Add or update an IP -> MAC binding. Called by DHCP clients on lease ACK
    // and by the DHCP server when issuing a lease.
    public static void bind(IPAddress ipAddress, MACAddress macAddress, int lanID) {
        IP_TO_MAC.put(ipAddress, macAddress);
        IP_TO_LAN.put(ipAddress, lanID);
    }

    // Remove an IP binding. Called on lease release or expiry.
    public static void unbind(IPAddress ipAddress) {
        IP_TO_MAC.remove(ipAddress);
        IP_TO_LAN.remove(ipAddress);
    }

    // Allowable client IP pool for a LAN. The high nibble is the LAN id; the low
    // nibble runs from 0x2..0xF (0x_0 is reserved as "unassigned" and 0x_1 is the
    // router gateway). Returns a fresh, mutable list each call.
    public static List<IPAddress> lanPool(int lanID) {
        if (lanID < 1 || lanID > 0xF) {
            throw new IllegalArgumentException("Unknown LAN ID: " + lanID);
        }
        List<IPAddress> pool = new ArrayList<>();
        for (int low = 0x2; low <= 0xF; low++) {
            pool.add(new IPAddress((lanID << 4) | low));
        }
        return pool;
    }
}
