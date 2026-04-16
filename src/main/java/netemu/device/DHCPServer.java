package netemu.device;

import netemu.common.AddressTable;
import netemu.common.DHCPMessage;
import netemu.common.IPAddress;
import netemu.common.Log;
import netemu.common.MACAddress;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

/**
 * DHCP server bound to a single router LAN interface. Owns an address pool and
 * lease table for one LAN segment. Pure logic — no networking; the router calls
 * handle(...) with decoded messages and forwards the responses back onto the wire.
 */
public final class DHCPServer {

    public static final int DEFAULT_LEASE_SECS = 60;

    private final int lanID;
    private final IPAddress serverIP;
    private final int leaseSecs;
    private final Log log;

    private final Deque<IPAddress> pool = new ArrayDeque<>();
    private final Set<IPAddress> reserved = new HashSet<>();
    private final Map<MACAddress, Lease> leases = new HashMap<>();
    private final Map<MACAddress, IPAddress> offered = new HashMap<>();
    private volatile Consumer<MACAddress> onLeaseExpired = mac -> {};

    public DHCPServer(int lanID, IPAddress serverIP, int leaseSecs, Log log) {
        this.lanID = lanID;
        this.serverIP = serverIP;
        this.leaseSecs = leaseSecs;
        this.log = log;
        initPool();
    }

    public DHCPServer(int lanID, IPAddress serverIP, Log log) {
        this(lanID, serverIP, DEFAULT_LEASE_SECS, log);
    }

    private void initPool() {
        // Reserve the gateway IP — the server itself sits on this address
        reserved.add(serverIP);
        for (IPAddress ip : AddressTable.lanPool(lanID)) {
            if (!reserved.contains(ip)) {
                pool.addLast(ip);
            }
        }
    }

    /**
     * Top-level dispatch. Returns a response to send back onto the LAN, or empty
     * if no response is required (RELEASE) or possible (pool exhausted).
     */
    public synchronized Optional<DHCPMessage> handle(DHCPMessage msg, long nowMillis) {
        expireLeases(nowMillis);
        return switch (msg.op()) {
            case DHCPMessage.OP_DISCOVER -> handleDiscover(msg);
            case DHCPMessage.OP_REQUEST  -> Optional.of(handleRequest(msg, nowMillis));
            case DHCPMessage.OP_RENEW    -> Optional.of(handleRenew(msg, nowMillis));
            case DHCPMessage.OP_RELEASE  -> { handleRelease(msg); yield Optional.empty(); }
            default -> Optional.empty();
        };
    }

    public Optional<DHCPMessage> handle(DHCPMessage msg) {
        return handle(msg, System.currentTimeMillis());
    }

    private Optional<DHCPMessage> handleDiscover(DHCPMessage msg) {
        MACAddress client = msg.clientMAC();

        // If this client already holds a lease, re-offer the same address (idempotent).
        Lease existing = leases.get(client);
        if (existing != null) {
            log.info("DHCP[LAN" + lanID + "]: re-offering " + existing.ip + " to " + client + " (existing lease)");
            offered.put(client, existing.ip);
            return Optional.of(DHCPMessage.offer(msg.xid(), client, existing.ip, serverIP, leaseSecs));
        }

        // If we already offered an address to this client and they re-DISCOVER, hand back the same one.
        IPAddress prevOffer = offered.get(client);
        if (prevOffer != null) {
            log.info("DHCP[LAN" + lanID + "]: re-offering " + prevOffer + " to " + client + " (pending offer)");
            return Optional.of(DHCPMessage.offer(msg.xid(), client, prevOffer, serverIP, leaseSecs));
        }

        // Prefer the spec-mandated IP for this client if it is still available in the pool.
        // This makes DHCP deterministic against the topology without sacrificing the feature.
        IPAddress assigned = AddressTable.preferredIPFor(client)
            .filter(pool::remove)
            .orElseGet(pool::pollFirst);
        if (assigned == null) {
            log.warn("DHCP[LAN" + lanID + "]: pool exhausted — no offer for " + client);
            return Optional.empty();
        }
        offered.put(client, assigned);
        log.info("DHCP[LAN" + lanID + "]: offering " + assigned + " to " + client);
        return Optional.of(DHCPMessage.offer(msg.xid(), client, assigned, serverIP, leaseSecs));
    }

    private DHCPMessage handleRequest(DHCPMessage msg, long nowMillis) {
        MACAddress client = msg.clientMAC();
        IPAddress requested = msg.yourIP();

        // Validate: the requested IP must match the address we offered to this client,
        // OR (recovery path) match an existing lease for this client.
        IPAddress pendingOffer = offered.get(client);
        Lease existing = leases.get(client);

        boolean matchesOffer = pendingOffer != null && pendingOffer.equals(requested);
        boolean matchesLease = existing != null && existing.ip.equals(requested);

        if (!matchesOffer && !matchesLease) {
            log.warn("DHCP[LAN" + lanID + "]: NAK to " + client + " — requested " + requested + " not offered/leased");
            return DHCPMessage.nak(msg.xid(), client, serverIP);
        }

        // Commit the lease
        offered.remove(client);
        Lease newLease = new Lease(requested, nowMillis + leaseSecs * 1000L);
        leases.put(client, newLease);
        AddressTable.bind(requested, client, lanID);
        log.info("DHCP[LAN" + lanID + "]: ACK — leased " + requested + " to " + client + " for " + leaseSecs + "s");
        return DHCPMessage.ack(msg.xid(), client, requested, serverIP, leaseSecs);
    }

    private DHCPMessage handleRenew(DHCPMessage msg, long nowMillis) {
        MACAddress client = msg.clientMAC();
        Lease existing = leases.get(client);
        if (existing == null || !existing.ip.equals(msg.yourIP())) {
            log.warn("DHCP[LAN" + lanID + "]: NAK renew from " + client + " for " + msg.yourIP() + " — no matching lease");
            return DHCPMessage.nak(msg.xid(), client, serverIP);
        }
        existing.expiresAt = nowMillis + leaseSecs * 1000L;
        log.info("DHCP[LAN" + lanID + "]: renewed " + existing.ip + " for " + client);
        return DHCPMessage.ack(msg.xid(), client, existing.ip, serverIP, leaseSecs);
    }

    private void handleRelease(DHCPMessage msg) {
        MACAddress client = msg.clientMAC();
        Lease existing = leases.remove(client);
        if (existing != null) {
            pool.addLast(existing.ip);
            AddressTable.unbind(existing.ip);
            log.info("DHCP[LAN" + lanID + "]: released " + existing.ip + " from " + client);
        }
    }

    private void expireLeases(long nowMillis) {
        var it = leases.entrySet().iterator();
        while (it.hasNext()) {
            var entry = it.next();
            if (entry.getValue().expiresAt <= nowMillis) {
                IPAddress ip = entry.getValue().ip;
                MACAddress mac = entry.getKey();
                pool.addLast(ip);
                AddressTable.unbind(ip);
                log.warn("DHCP[LAN" + lanID + "]: lease expired — " + ip + " reclaimed from " + mac);
                it.remove();
                onLeaseExpired.accept(mac);
            }
        }
    }

    /**
     * Register a callback invoked whenever a lease is reaped due to expiry. The
     * router uses this to notify the IDS so that snooped MAC-IP bindings stay in
     * sync with the actual lease state.
     */
    public void setOnLeaseExpired(Consumer<MACAddress> consumer) {
        this.onLeaseExpired = consumer == null ? mac -> {} : consumer;
    }

    public synchronized int poolSize() { return pool.size(); }
    public synchronized int leaseCount() { return leases.size(); }

    public synchronized Optional<IPAddress> leaseFor(MACAddress mac) {
        Lease lease = leases.get(mac);
        return lease == null ? Optional.empty() : Optional.of(lease.ip);
    }

    public int lanID() { return lanID; }
    public IPAddress serverIP() { return serverIP; }
    public int leaseSecs() { return leaseSecs; }

    private static final class Lease {
        final IPAddress ip;
        long expiresAt;

        Lease(IPAddress ip, long expiresAt) {
            this.ip = ip;
            this.expiresAt = expiresAt;
        }
    }
}
