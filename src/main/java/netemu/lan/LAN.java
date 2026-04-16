package netemu.lan;

import netemu.common.Log;
import netemu.common.Ansi;
import netemu.common.EthernetFrame;
import netemu.common.IPPacket;
import netemu.common.ARPMessage;
import netemu.common.AddressTable;
import netemu.common.MACAddress;

import java.io.IOException;
import java.net.InetAddress;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;

public class LAN {

    private final Log log;
    private final int lanID;
    private final int portNumber;
    private final ConcurrentHashMap<String, InetSocketAddress> endpoints = new ConcurrentHashMap<>();
    private volatile boolean dynamicARPInspectionEnabled = false;
    private int daiDropCount = 0;

    public LAN(int lanID, int portNumber) {
        this.lanID = lanID;
        this.portNumber = portNumber;
        this.log = new Log("LAN" + lanID, Ansi.CYAN);
    }

    public void start() throws IOException {
        DatagramSocket socket = new DatagramSocket(portNumber);
        Ansi.banner("LAN" + lanID + " Emulator (port " + portNumber + ")", Ansi.CYAN);
        log.info("Listening on port " + portNumber);
        startCLI();

        byte[] buffer = new byte[1024];
        while (true) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);

            byte[] data = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), packet.getOffset(), data, 0, packet.getLength());

            String message = new String(data);
            InetSocketAddress sender = new InetSocketAddress(packet.getAddress(), packet.getPort());

            if (message.startsWith("REGISTER ")) {
                handleRegister(message, packet.getAddress(), sender);
            } else {
                handleFrame(data, sender, socket);
            }
        }
    }

    private void handleRegister(String message, InetAddress address, InetSocketAddress senderAddress) {
        String[] parts = message.trim().split("\\s+");
        if (parts.length >= 3) {
            String mac = parts[1];
            int devicePortNumber = Integer.parseInt(parts[2]);
            InetSocketAddress endpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), devicePortNumber);
            endpoints.put(mac, endpoint);
            log.info("Device " + mac + " joined (port " + devicePortNumber + ")");
        }
    }

    private void handleFrame(byte[] data, InetSocketAddress senderAddress, DatagramSocket socket) {
        try {
            EthernetFrame frame = EthernetFrame.decode(data);

            if (shouldDropByDAI(frame)) {
                return;
            }

            // Build the full RX-and-fanout tree first, then emit it as a single
            // atomic event so that concurrent frames from multiple senders don't
            // interleave their forwarding lines.
            String srcMac = frame.sourceMACAddress().value();
            java.util.List<String> children = new java.util.ArrayList<>();
            for (var entry : endpoints.entrySet()) {
                if (!entry.getKey().equals(srcMac)) {
                    InetSocketAddress target = entry.getValue();
                    DatagramPacket out = new DatagramPacket(data, data.length, target);
                    socket.send(out);
                    children.add("  └─ forwarded to " + entry.getKey() + " (port " + target.getPort() + ")");
                }
            }
            log.event("RX Received " + frame, children.toArray(new String[0]));
        } catch (Exception e) {
            log.error("Failed to broadcast frame: " + e.getMessage());
        }
    }

    private boolean shouldDropByDAI(EthernetFrame frame) {
        if (!dynamicARPInspectionEnabled) {
            return false;
        }

        try {
            IPPacket packet = IPPacket.decode(frame.data());
            if (packet.protocol() != IPPacket.PROTOCOL_ARP) {
                return false;
            }

            ARPMessage arp = ARPMessage.decode(packet.data());
            if (!arp.isReply()) {
                return false;
            }

            Optional<MACAddress> expected = AddressTable.resolve(arp.senderIP());
            if (expected.isEmpty()) {
                // Unknown sender in static table; keep behavior permissive for compatibility.
                return false;
            }
            MACAddress expectedMACAddress = expected.get();
            boolean payloadMismatch = !expectedMACAddress.equals(arp.senderMAC());
            boolean frameMismatch = !expectedMACAddress.equals(frame.sourceMACAddress());

            if (payloadMismatch || frameMismatch) {
                daiDropCount++;
                log.security("DAI(LAN" + lanID + "): dropped forged ARP reply claim=" + arp.senderIP() +
                        " is-at " + arp.senderMAC() + " (frame src=" + frame.sourceMACAddress() +
                        ", expected=" + expectedMACAddress + ")");
                return true;
            }
        } catch (IllegalArgumentException e) {
            // Unknown sender in static table; keep behavior permissive for compatibility.
        } catch (Exception e) {
            log.error("DAI inspection error: " + e.getMessage());
        }

        return false;
    }

    private void startCLI() {
        Thread t = new Thread(() -> {
            try (Scanner scanner = new Scanner(System.in)) {
                printHelp();
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine().trim();
                    if (line.isEmpty()) {
                        continue;
                    }

                    String[] parts = line.split("\\s+");
                    String cmd = parts[0].toLowerCase();
                    switch (cmd) {
                        case "dai" -> handleDAICommand(parts);
                        case "info" -> printInfo();
                        case "help" -> printHelp();
                        default -> System.out.println("Unknown command. Type 'help'.");
                    }
                }
            } catch (Exception e) {
                log.error("CLI error: " + e.getMessage());
            }
        }, "LAN" + lanID + "-cli");
        t.setDaemon(true);
        t.start();
    }

    private void handleDAICommand(String[] parts) {
        if (parts.length < 2) {
            System.out.println("Usage: dai <on|off|status>");
            return;
        }

        switch (parts[1].toLowerCase()) {
            case "on" -> {
                dynamicARPInspectionEnabled = true;
                log.security("DAI ON (LAN-side) — forged ARP replies will be dropped before broadcast");
            }
            case "off" -> {
                dynamicARPInspectionEnabled = false;
                log.info("DAI OFF (LAN-side)");
            }
            case "status" -> {
                log.info("DAI status: " + (dynamicARPInspectionEnabled ? "ON" : "OFF") +
                        " | dropped forged ARP replies: " + daiDropCount);
            }
            default -> System.out.println("Usage: dai <on|off|status>");
        }
    }

    private void printInfo() {
        log.info("LAN" + lanID + " info: endpoints=" + endpoints.size() +
                ", DAI=" + (dynamicARPInspectionEnabled ? "ON" : "OFF") +
                ", DAI drops=" + daiDropCount);
    }

    private void printHelp() {
        log.block(
            "┌─ LAN" + lanID + " Commands ──────────────────────────────",
            "│  dai on | off | status   Toggle/view LAN-side Dynamic ARP Inspection",
            "│  info                    Show LAN state",
            "│  help                    Show this help",
            "└─────────────────────────────────────────────────────"
        );
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("Usage: LanEmulator <lanId> <port>");
            System.exit(1);
        }
        int lanId = Integer.parseInt(args[0]);
        int port = Integer.parseInt(args[1]);
        new LAN(lanId, port).start();
    }
}
