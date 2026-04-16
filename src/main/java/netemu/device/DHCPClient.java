package netemu.device;

import netemu.common.AddressTable;
import netemu.common.DHCPMessage;
import netemu.common.EthernetFrame;
import netemu.common.IPAddress;
import netemu.common.IPPacket;
import netemu.common.Log;
import netemu.common.MACAddress;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * DHCP client used by a Node during startup to acquire an IP lease.
 *
 * State machine: INIT --DISCOVER--> SELECTING --OFFER--> REQUESTING --ACK--> BOUND
 * On NAK or timeout, retries with exponential backoff up to MAX_RETRIES attempts.
 *
 * Threading model: the Node's receiver thread feeds incoming DHCP messages via
 * deliver(); the main startup thread blocks in acquireLease() polling the inbox.
 */
public final class DHCPClient {

    private static final long INITIAL_TIMEOUT_MS = 2000;
    private static final int MAX_RETRIES = 5;

    private final MACAddress clientMAC;
    private final NetworkInterface networkInterfaceCard;
    private final DatagramSocket socket;
    private final InetSocketAddress lanEmulatorAddress;
    private final Log log;
    private final Random random = new Random();

    private final BlockingQueue<DHCPMessage> inbox = new LinkedBlockingQueue<>();

    public DHCPClient(NetworkInterface networkInterfaceCard, DatagramSocket socket,
                      InetSocketAddress lanEmulatorAddress, Log log) {
        this.networkInterfaceCard = networkInterfaceCard;
        this.clientMAC = networkInterfaceCard.macAddress();
        this.socket = socket;
        this.lanEmulatorAddress = lanEmulatorAddress;
        this.log = log;
    }

    /**
     * Called by the Node receiver thread when a DHCP message arrives. Filters
     * out messages destined for other clients so the inbox only ever contains
     * messages relevant to this client.
     */
    public void deliver(DHCPMessage msg) {
        if (msg.clientMAC().equals(clientMAC)) {
            inbox.offer(msg);
        }
    }

    /**
     * Run the DISCOVER/REQUEST handshake. Returns true on successful lease,
     * false if all retries are exhausted. On success, mutates the NIC and the
     * AddressTable so the rest of the node sees the new IP.
     */
    public boolean acquireLease() throws IOException {
        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            int xid = random.nextInt(0x10000);
            inbox.clear();

            long timeoutMs = INITIAL_TIMEOUT_MS * (1L << attempt);

            sendDiscover(xid);
            DHCPMessage offer = waitFor(xid, DHCPMessage.OP_OFFER, timeoutMs);
            if (offer == null) {
                log.warn("DHCP: no OFFER received (attempt " + (attempt + 1) + "/" + MAX_RETRIES + ")");
                continue;
            }
            log.info("DHCP: got OFFER " + offer.yourIP() + " from server " + offer.serverIP());

            sendRequest(xid, offer.yourIP(), offer.serverIP());
            DHCPMessage reply = waitForAckOrNak(xid, timeoutMs);
            if (reply == null) {
                log.warn("DHCP: no ACK/NAK received (attempt " + (attempt + 1) + "/" + MAX_RETRIES + ")");
                continue;
            }
            if (reply.isNak()) {
                log.warn("DHCP: server NAK'd request — retrying");
                continue;
            }
            if (reply.isAck()) {
                IPAddress leasedIP = reply.yourIP();
                networkInterfaceCard.assignIP(leasedIP);
                AddressTable.bind(leasedIP, clientMAC, networkInterfaceCard.lanID());
                log.info("DHCP: ACK — leased " + leasedIP + " for " + reply.leaseSecs() + "s (gateway " + reply.serverIP() + ")");
                return true;
            }
        }
        return false;
    }

    private void sendDiscover(int xid) throws IOException {
        DHCPMessage msg = DHCPMessage.discover(xid, clientMAC);
        sendDHCP(msg);
        log.info("DHCP: sent DISCOVER xid=0x" + Integer.toHexString(xid));
    }

    private void sendRequest(int xid, IPAddress requestedIP, IPAddress serverIP) throws IOException {
        DHCPMessage msg = DHCPMessage.request(xid, clientMAC, requestedIP, serverIP);
        sendDHCP(msg);
        log.info("DHCP: sent REQUEST for " + requestedIP + " xid=0x" + Integer.toHexString(xid));
    }

    private void sendDHCP(DHCPMessage msg) throws IOException {
        // Source IP is 0x00 (unassigned), destination is broadcast IP. The link-layer
        // destination is the broadcast MAC so the LAN emulator fans the frame out to
        // every endpoint, including the router which hosts the DHCP server.
        IPPacket packet = IPPacket.dhcp(DHCPMessage.UNASSIGNED_IP, DHCPMessage.BROADCAST_IP, msg.encode());
        EthernetFrame frame = new EthernetFrame(clientMAC, MACAddress.BROADCAST, packet.encode());
        byte[] data = frame.encode();
        DatagramPacket udp = new DatagramPacket(data, data.length, lanEmulatorAddress);
        socket.send(udp);
    }

    private DHCPMessage waitFor(int xid, byte expectedOp, long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (true) {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) return null;
            try {
                DHCPMessage msg = inbox.poll(remaining, TimeUnit.MILLISECONDS);
                if (msg == null) return null;
                if (msg.xid() == xid && msg.op() == expectedOp) return msg;
                // Otherwise discard and keep waiting
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
    }

    private DHCPMessage waitForAckOrNak(int xid, long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (true) {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) return null;
            try {
                DHCPMessage msg = inbox.poll(remaining, TimeUnit.MILLISECONDS);
                if (msg == null) return null;
                if (msg.xid() == xid && (msg.isAck() || msg.isNak())) return msg;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
    }
}
