package netemu.device;

import netemu.common.*;

import java.io.IOException;

/**
 * Node 3
 *  - Role: Firewall node on LAN2
 *      - Has an integrated firewall that can block packets by the Source IP Address
 *  - MAC Address: N3
 *  - IP Address: 0x22
 *  - Port Number: 6003
 *  - LAN ID: 2
 */
public class Node3 extends Node {

    private final Firewall firewall;

    public Node3() {
        super("Node3", new NetworkInterface(AddressTable.MAC_N3, AddressTable.IP_N3, 2, AddressTable.NODE3_PORT, AddressTable.LAN2_PORT), Ansi.BLUE);
        this.firewall = new Firewall(log);
    }

    @Override
    protected String logColor() {
        return Ansi.BLUE;
    }

    @Override
    protected void handleIPPacket(IPPacket packet, EthernetFrame frame) {
        // Check firewall before processing
        if (firewall.shouldBlock(packet)) {
            return; // Dropped by firewall
        }
        super.handleIPPacket(packet, frame);
    }

    @Override
    protected boolean handleCommand(String line) {
        String[] parts = line.split("\\s+");
        String cmd = parts[0].toLowerCase();

        if ("fw".equals(cmd)) {
            handleFirewallCommand(parts);
            return true;
        }
        return super.handleCommand(line);
    }

    private void handleFirewallCommand(String[] parts) {
        if (parts.length < 2) {
            printFirewallHelp();
            return;
        }
        switch (parts[1].toLowerCase()) {
            case "add" -> {
                if (parts.length >= 5 && "block".equalsIgnoreCase(parts[2]) && "src".equalsIgnoreCase(parts[3])) {
                    IPAddress ipAddress = IPAddress.parse(parts[4]);
                    firewall.blockSourceIPAddress(ipAddress);
                } else {
                    printFirewallHelp();
                }
            }
            case "remove" -> {
                if (parts.length >= 5 && "block".equalsIgnoreCase(parts[2]) && "src".equalsIgnoreCase(parts[3])) {
                    IPAddress ipAddress = IPAddress.parse(parts[4]);
                    firewall.unblockSourceIPAddress(ipAddress);
                } else {
                    printFirewallHelp();
                }
            }
            case "on" -> { firewall.setEnabled(true); log.info("Firewall ON — filtering incoming packets"); }
            case "off" -> { firewall.setEnabled(false); log.info("Firewall OFF — all packets allowed"); }
            case "status" -> firewall.printStatus();
            default -> printFirewallHelp();
        }
    }

    private void printFirewallHelp() {
        log.block(
            "┌─ Firewall Commands ───────────────────",
            "│  fw add block src <IP>    Block a source IP",
            "│  fw remove block src <IP> Unblock a source IP",
            "│  fw on | off              Enable / disable firewall",
            "│  fw status                Show firewall status",
            "└───────────────────────────────────────"
        );
    }

    @Override
    protected void appendExtraHelp(java.util.List<String> lines) {
        lines.add("│  ─── firewall ───");
        lines.add("│  fw …                        Firewall commands (type 'fw' for details)");
    }

    public static void main(String[] args) throws IOException {
        boolean useStatic = args.length > 0 && "--static".equalsIgnoreCase(args[0]);
        new Node3().start(!useStatic);
    }
}
