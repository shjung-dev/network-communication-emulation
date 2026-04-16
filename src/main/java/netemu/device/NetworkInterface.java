package netemu.device;

import java.util.Objects;

import netemu.common.IPAddress;
import netemu.common.MACAddress;

/**
 * Network interface card. Holds the MAC, LAN id, and port numbers (immutable)
 * plus the currently assigned IP address (mutable — set statically at construction
 * for legacy/static mode, or assigned at runtime by a DHCP client).
 */
public final class NetworkInterface {

    private final MACAddress macAddress;
    private final int lanID;
    private final int devicePortNumber;
    private final int lanEmulatorPortNumber;

    // Mutable: nodes booting via DHCP start with no IP and have one assigned later.
    private volatile IPAddress ipAddress;

    public NetworkInterface(MACAddress macAddress, IPAddress ipAddress, int lanID,
                            int devicePortNumber, int lanEmulatorPortNumber) {
        this.macAddress = macAddress;
        this.ipAddress = ipAddress;
        this.lanID = lanID;
        this.devicePortNumber = devicePortNumber;
        this.lanEmulatorPortNumber = lanEmulatorPortNumber;
    }

    public MACAddress macAddress() { return macAddress; }
    public IPAddress ipAddress() { return ipAddress; }
    public int lanID() { return lanID; }
    public int devicePortNumber() { return devicePortNumber; }
    public int lanEmulatorPortNumber() { return lanEmulatorPortNumber; }

    public boolean hasIP() { return ipAddress != null; }

    public void assignIP(IPAddress newIP) { this.ipAddress = newIP; }

    public void releaseIP() { this.ipAddress = null; }

    @Override
    public String toString() {
        String ipStr = ipAddress == null ? "(none)" : ipAddress.toString();
        return String.format("Interface [MAC=%s | IP=%s | LAN%d | port %d]",
                macAddress, ipStr, lanID, devicePortNumber);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof NetworkInterface that)) return false;
        return lanID == that.lanID
                && devicePortNumber == that.devicePortNumber
                && lanEmulatorPortNumber == that.lanEmulatorPortNumber
                && Objects.equals(macAddress, that.macAddress)
                && Objects.equals(ipAddress, that.ipAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(macAddress, ipAddress, lanID, devicePortNumber, lanEmulatorPortNumber);
    }
}
