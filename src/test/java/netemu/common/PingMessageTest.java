package netemu.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PingMessageTest {

    @Test
    void requestCreatesEchoRequest() {
        PingMessage ping = PingMessage.request(5);
        assertTrue(ping.isRequest());
        assertFalse(ping.isReply());
        assertEquals(PingMessage.ECHO_REQUEST, ping.type());
        assertEquals(5, ping.sequence());
    }

    @Test
    void requestTimestampIsApproximatelyNow() {
        long before = System.currentTimeMillis();
        PingMessage ping = PingMessage.request(1);
        long after = System.currentTimeMillis();
        assertTrue(ping.timestamp() >= before);
        assertTrue(ping.timestamp() <= after);
    }

    @Test
    void toReplyPreservesSequenceAndTimestamp() {
        PingMessage request = PingMessage.request(7);
        PingMessage reply = request.toReply();

        assertTrue(reply.isReply());
        assertFalse(reply.isRequest());
        assertEquals(PingMessage.ECHO_REPLY, reply.type());
        assertEquals(request.sequence(), reply.sequence());
        assertEquals(request.timestamp(), reply.timestamp());
    }

    @Test
    void encodeProducesTenBytes() {
        PingMessage ping = PingMessage.request(1);
        byte[] encoded = ping.encode();
        assertEquals(PingMessage.SIZE, encoded.length);
    }

    @Test
    void encodeDecodeRoundTrip() {
        PingMessage original = PingMessage.request(42);
        byte[] encoded = original.encode();
        PingMessage decoded = PingMessage.decode(encoded);

        assertEquals(original.type(), decoded.type());
        assertEquals(original.sequence(), decoded.sequence());
        assertEquals(original.timestamp(), decoded.timestamp());
    }

    @Test
    void encodeDecodeReplyRoundTrip() {
        PingMessage reply = PingMessage.request(3).toReply();
        byte[] encoded = reply.encode();
        PingMessage decoded = PingMessage.decode(encoded);

        assertTrue(decoded.isReply());
        assertEquals(3, decoded.sequence());
        assertEquals(reply.timestamp(), decoded.timestamp());
    }

    @Test
    void decodeRejectsTooShort() {
        byte[] tooShort = new byte[9];
        assertThrows(IllegalArgumentException.class, () -> PingMessage.decode(tooShort));
    }

    @Test
    void sequenceFieldIsUnsigned() {
        PingMessage ping = new PingMessage(PingMessage.ECHO_REQUEST, 255, System.currentTimeMillis());
        byte[] encoded = ping.encode();
        PingMessage decoded = PingMessage.decode(encoded);
        assertEquals(255, decoded.sequence());
    }

    @Test
    void timestampPreservesFullLongRange() {
        long ts = 0x0102030405060708L;
        PingMessage ping = new PingMessage(PingMessage.ECHO_REQUEST, 1, ts);
        byte[] encoded = ping.encode();
        PingMessage decoded = PingMessage.decode(encoded);
        assertEquals(ts, decoded.timestamp());
    }

    @Test
    void rttIsNonNegative() {
        PingMessage ping = PingMessage.request(1);
        assertTrue(ping.RTT() >= 0);
    }

    @Test
    void typeConstantsMatchICMP() {
        assertEquals(0x08, PingMessage.ECHO_REQUEST);
        assertEquals(0x00, PingMessage.ECHO_REPLY);
    }

    @Test
    void toStringContainsType() {
        PingMessage req = PingMessage.request(1);
        assertTrue(req.toString().contains("REQUEST"));

        PingMessage rep = req.toReply();
        assertTrue(rep.toString().contains("REPLY"));
    }
}
