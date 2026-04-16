package netemu.common;

/**
 * Text Message Protocol
 * Format of Raw Text Message: [encrypted:1][text-length:1][text:up to 254]
 *
 * Supports plaintext and encrypted modes.
 * Encrypted mode uses XOR cipher with a shared key to demonstrate
 * confidentiality as a defense against sniffing attacks.
 */
public class TextMessage {

    public static final int HEADER_SIZE = 2;
    public static final int MAX_TEXT_LENGTH = 254;
    public static final byte PLAINTEXT = 0x00;
    public static final byte ENCRYPTED = 0x01;

    private static final byte XOR_KEY = 0x5A;

    private final byte encrypted;
    private final String text;

    public TextMessage(byte encrypted, String text) {
        if (text.length() > MAX_TEXT_LENGTH) {
            throw new IllegalArgumentException("Text exceeds max length of " + MAX_TEXT_LENGTH + ": " + text.length());
        }
        this.encrypted = encrypted;
        this.text = text;
    }

    // Create a plaintext message
    public static TextMessage plaintext(String text) {
        return new TextMessage(PLAINTEXT, text);
    }

    // Create an encrypted message
    public static TextMessage encrypted(String text) {
        return new TextMessage(ENCRYPTED, text);
    }

    // Encode into raw bytes (encrypts text if encrypted mode)
    public byte[] encode() {
        byte[] textBytes = text.getBytes();
        if (isEncrypted()) {
            textBytes = xor(textBytes);
        }
        byte[] result = new byte[HEADER_SIZE + textBytes.length];
        result[0] = encrypted;
        result[1] = (byte) textBytes.length;
        System.arraycopy(textBytes, 0, result, HEADER_SIZE, textBytes.length);
        return result;
    }

    // Decode raw bytes into a TextMessage (decrypts if encrypted)
    public static TextMessage decode(byte[] data) {
        if (data.length < HEADER_SIZE) {
            throw new IllegalArgumentException("Text message too short: " + data.length);
        }
        byte encrypted = data[0];
        int textLength = data[1] & 0xFF;
        byte[] textBytes = new byte[textLength];
        System.arraycopy(data, HEADER_SIZE, textBytes, 0, textLength);

        if (encrypted == ENCRYPTED) {
            textBytes = xor(textBytes);
        }
        return new TextMessage(encrypted, new String(textBytes));
    }

    // Decode raw bytes WITHOUT decrypting (for sniffing — shows raw encrypted data)
    public static TextMessage decodeRaw(byte[] data) {
        if (data.length < HEADER_SIZE) {
            throw new IllegalArgumentException("Text message too short: " + data.length);
        }
        byte encrypted = data[0];
        int textLength = data[1] & 0xFF;
        byte[] textBytes = new byte[textLength];
        System.arraycopy(data, HEADER_SIZE, textBytes, 0, textLength);
        return new TextMessage(encrypted, new String(textBytes));
    }

    private static byte[] xor(byte[] data) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ XOR_KEY);
        }
        return result;
    }

    public boolean isEncrypted() {
        return encrypted == ENCRYPTED;
    }

    public String text() {
        return text;
    }

    public byte encryptedFlag() {
        return encrypted;
    }

    @Override
    public String toString() {
        return String.format("Message %s \"%s\"", isEncrypted() ? "[ENCRYPTED]" : "[PLAIN]", text);
    }
}
