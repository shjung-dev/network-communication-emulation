package netemu.device;

import netemu.common.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NetworkInterfaceTest {

    @Test
    void recordFieldsAccessible() {
        NetworkInterface nic = new NetworkInterface(
                new MACAddress("N1"), new IPAddress(0x12), 1, 6001, 5001);
        assertEquals("N1", nic.macAddress().value());
        assertEquals(0x12, nic.ipAddress().value());
        assertEquals(1, nic.lanID());
        assertEquals(6001, nic.devicePortNumber());
        assertEquals(5001, nic.lanEmulatorPortNumber());
    }

    @Test
    void toStringContainsFields() {
        NetworkInterface nic = new NetworkInterface(
                new MACAddress("R2"), new IPAddress(0x21), 2, 6012, 5002);
        String str = nic.toString();
        assertTrue(str.contains("R2"));
        assertTrue(str.contains("0x21"));
        assertTrue(str.contains("Interface"));
    }

    @Test
    void equalityBasedOnAllFields() {
        NetworkInterface a = new NetworkInterface(
                new MACAddress("N1"), new IPAddress(0x12), 1, 6001, 5001);
        NetworkInterface b = new NetworkInterface(
                new MACAddress("N1"), new IPAddress(0x12), 1, 6001, 5001);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void inequalityOnDifferentFields() {
        NetworkInterface a = new NetworkInterface(
                new MACAddress("N1"), new IPAddress(0x12), 1, 6001, 5001);
        NetworkInterface b = new NetworkInterface(
                new MACAddress("N2"), new IPAddress(0x13), 1, 6002, 5001);
        assertNotEquals(a, b);
    }
}
