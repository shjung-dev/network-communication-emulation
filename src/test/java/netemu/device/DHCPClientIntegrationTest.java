package netemu.device;

import netemu.common.AddressTable;
import netemu.common.Ansi;
import netemu.common.DHCPMessage;
import netemu.common.EthernetFrame;
import netemu.common.IPAddress;
import netemu.common.IPPacket;
import netemu.common.Log;
import netemu.common.MACAddress;
import netemu.lan.LAN;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end test that boots a real LAN emulator and a fake router (running an
 * actual DHCPServer) on non-standard ports, then drives a DHCPClient through
 * the full DISCOVER/OFFER/REQUEST/ACK handshake over real UDP sockets.
 *
 * Uses ports in the 17xxx range to avoid colliding with the standard 5xxx/6xxx
 * ports a running netemu would use.
 */
class DHCPClientIntegrationTest {

    private static final int TEST_LAN_PORT    = 17001;
    private static final int TEST_ROUTER_PORT = 17011;
    private static final int TEST_CLIENT_PORT = 17021;
    private static final int TEST_LAN_ID      = 1;

    private LAN lan;
    private Thread lanThread;
    private Thread routerThread;
    private Thread clientReceiverThread;
    private DatagramSocket clientSocket;
    private DatagramSocket routerSocket;
    private final AtomicBoolean shutdown = new AtomicBoolean(false);

    @BeforeEach
    void setUp() {
        // Make sure the static seed for N1 is gone before the test runs.
        AddressTable.unbind(AddressTable.IP_N1);
        AddressTable.unbind(AddressTable.IP_N2);
    }

    @AfterEach
    void tearDown() throws Exception {
        shutdown.set(true);
        if (clientSocket != null) clientSocket.close();
        if (routerSocket != null) routerSocket.close();
        if (lanThread != null) lanThread.interrupt();
        if (routerThread != null) routerThread.interrupt();
        if (clientReceiverThread != null) clientReceiverThread.interrupt();

        // Restore the static seed for other tests
        AddressTable.bind(AddressTable.IP_N1, AddressTable.MAC_N1, 1);
        AddressTable.bind(AddressTable.IP_N2, AddressTable.MAC_N2, 1);
        for (IPAddress ip : AddressTable.lanPool(1)) {
            if (!ip.equals(AddressTable.IP_N1) && !ip.equals(AddressTable.IP_N2) && !ip.equals(AddressTable.IP_R1)) {
                AddressTable.unbind(ip);
            }
        }
    }

    @Test
    void clientAcquiresLeaseViaRealSockets() throws Exception {
        // 1. Boot a real LAN emulator on a non-standard port
        lan = new LAN(TEST_LAN_ID, TEST_LAN_PORT);
        lanThread = new Thread(() -> {
            try { lan.start(); } catch (IOException ignored) {}
        }, "test-lan");
        lanThread.setDaemon(true);
        lanThread.start();

        // 2. Boot a fake router that registers with the LAN and runs a DHCPServer
        Log routerLog = new Log("TestRouter", Ansi.PURPLE);
        DHCPServer dhcpServer = new DHCPServer(TEST_LAN_ID, AddressTable.IP_R1, 60, routerLog);
        InetSocketAddress lanAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), TEST_LAN_PORT);
        routerSocket = new DatagramSocket(TEST_ROUTER_PORT);
        registerWithLAN(routerSocket, lanAddress, AddressTable.MAC_R1, TEST_ROUTER_PORT);

        routerThread = new Thread(() -> runFakeRouter(routerSocket, lanAddress, dhcpServer, AddressTable.MAC_R1), "test-router");
        routerThread.setDaemon(true);
        routerThread.start();

        // Give the LAN and router a moment to bind and exchange registration
        Thread.sleep(150);

        // 3. Boot a fake client with no IP yet
        clientSocket = new DatagramSocket(TEST_CLIENT_PORT);
        registerWithLAN(clientSocket, lanAddress, AddressTable.MAC_N1, TEST_CLIENT_PORT);
        Thread.sleep(50);

        NetworkInterface clientNIC = new NetworkInterface(
                AddressTable.MAC_N1, null, TEST_LAN_ID, TEST_CLIENT_PORT, TEST_LAN_PORT);

        Log clientLog = new Log("TestClient", Ansi.GREEN);
        DHCPClient dhcpClient = new DHCPClient(clientNIC, clientSocket, lanAddress, clientLog);

        // 4. Run a tiny client receiver thread that decodes frames and feeds DHCP to the client
        clientReceiverThread = new Thread(() -> runClientReceiver(clientSocket, dhcpClient, AddressTable.MAC_N1), "test-client-rx");
        clientReceiverThread.setDaemon(true);
        clientReceiverThread.start();

        // 5. Run the handshake
        boolean leased = dhcpClient.acquireLease();
        assertTrue(leased, "DHCPClient should successfully acquire a lease");
        assertNotNull(clientNIC.ipAddress(), "NIC should have an IP after lease");
        assertEquals(TEST_LAN_ID, clientNIC.ipAddress().lanID(), "Leased IP should be in this LAN's high nibble");
        assertEquals(AddressTable.MAC_N1, AddressTable.resolve(clientNIC.ipAddress()).orElseThrow(),
                "AddressTable should reflect the new binding");
    }

    private void registerWithLAN(DatagramSocket socket, InetSocketAddress lanAddress,
                                 MACAddress mac, int port) throws IOException {
        String msg = "REGISTER " + mac.value() + " " + port;
        byte[] data = msg.getBytes();
        socket.send(new DatagramPacket(data, data.length, lanAddress));
    }

    private void runFakeRouter(DatagramSocket socket, InetSocketAddress lanAddress,
                               DHCPServer server, MACAddress routerMAC) {
        byte[] buffer = new byte[1024];
        while (!shutdown.get() && !socket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                byte[] data = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), data, 0, packet.getLength());

                EthernetFrame frame = EthernetFrame.decode(data);
                IPPacket inner = IPPacket.decode(frame.data());
                if (inner.protocol() != IPPacket.PROTOCOL_DHCP) continue;

                DHCPMessage dhcp = DHCPMessage.decode(inner.data());
                Optional<DHCPMessage> response = server.handle(dhcp);
                if (response.isEmpty()) continue;

                DHCPMessage reply = response.get();
                IPPacket replyPacket = IPPacket.dhcp(AddressTable.IP_R1, DHCPMessage.BROADCAST_IP, reply.encode());
                EthernetFrame replyFrame = new EthernetFrame(routerMAC, reply.clientMAC(), replyPacket.encode());
                byte[] replyData = replyFrame.encode();
                socket.send(new DatagramPacket(replyData, replyData.length, lanAddress));
            } catch (Exception e) {
                if (shutdown.get() || socket.isClosed()) return;
            }
        }
    }

    private void runClientReceiver(DatagramSocket socket, DHCPClient client, MACAddress clientMAC) {
        byte[] buffer = new byte[1024];
        while (!shutdown.get() && !socket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                byte[] data = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), data, 0, packet.getLength());

                EthernetFrame frame = EthernetFrame.decode(data);
                // MAC filter: accept frames addressed to us or broadcast
                if (!frame.destinationMACAddress().equals(clientMAC) && !frame.destinationMACAddress().isBroadcast()) {
                    continue;
                }
                IPPacket inner = IPPacket.decode(frame.data());
                if (inner.protocol() != IPPacket.PROTOCOL_DHCP) continue;

                DHCPMessage dhcp = DHCPMessage.decode(inner.data());
                client.deliver(dhcp);
            } catch (Exception e) {
                if (shutdown.get() || socket.isClosed()) return;
            }
        }
    }
}
