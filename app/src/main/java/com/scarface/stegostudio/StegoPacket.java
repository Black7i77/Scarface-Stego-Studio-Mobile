package com.scarface.stegostudio;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.CRC32;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Scarface Stego Studio packet formats.
 *
 * Legacy SCSTEG01 (desktop/mobile compatible):
 *   magic[8] | payloadLength u32 BE | CRC32 u32 BE | UTF-8 payload
 *
 * Encrypted SCSTEG02:
 *   magic[8] | ciphertextLength u32 BE | PBKDF2 iterations u32 BE |
 *   salt[16] | nonce[12] | AES-256-GCM ciphertext+tag
 *
 * The complete SCSTEG02 header is authenticated as AES-GCM AAD.
 */
public final class StegoPacket {
    public static final byte[] MAGIC_V1 = "SCSTEG01".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] MAGIC_V2 = "SCSTEG02".getBytes(StandardCharsets.US_ASCII);

    public static final int MAGIC_BYTES = 8;
    public static final int LEGACY_HEADER_BYTES = 16;
    public static final int ENCRYPTED_HEADER_BYTES = 44;
    public static final int SALT_BYTES = 16;
    public static final int NONCE_BYTES = 12;
    public static final int GCM_TAG_BYTES = 16;
    public static final int PBKDF2_ITERATIONS = 210_000;
    public static final int KEY_BITS = 256;

    private static final SecureRandom RNG = new SecureRandom();

    private StegoPacket() {}

    /** Kept for compatibility with older callers; creates SCSTEG01. */
    public static byte[] build(String message) {
        return buildLegacy(message);
    }

    public static byte[] buildLegacy(String message) {
        byte[] payload = message.getBytes(StandardCharsets.UTF_8);
        CRC32 crc = new CRC32();
        crc.update(payload);
        ByteBuffer b = ByteBuffer.allocate(LEGACY_HEADER_BYTES + payload.length).order(ByteOrder.BIG_ENDIAN);
        b.put(MAGIC_V1);
        b.putInt(payload.length);
        b.putInt((int) crc.getValue());
        b.put(payload);
        return b.array();
    }

    public static byte[] buildEncrypted(String message, char[] password) throws StegoException {
        if (password == null || password.length < 8) {
            throw new StegoException("Use an encryption password of at least 8 characters.");
        }

        byte[] plain = message.getBytes(StandardCharsets.UTF_8);
        byte[] salt = new byte[SALT_BYTES];
        byte[] nonce = new byte[NONCE_BYTES];
        RNG.nextBytes(salt);
        RNG.nextBytes(nonce);

        // GCM appends a 128-bit (16-byte) authentication tag.
        int cipherLength = plain.length + GCM_TAG_BYTES;
        ByteBuffer header = ByteBuffer.allocate(ENCRYPTED_HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        header.put(MAGIC_V2);
        header.putInt(cipherLength);
        header.putInt(PBKDF2_ITERATIONS);
        header.put(salt);
        header.put(nonce);
        byte[] headerBytes = header.array();

        byte[] keyBytes = null;
        try {
            keyBytes = deriveKey(password, salt, PBKDF2_ITERATIONS);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(headerBytes);
            byte[] encrypted = cipher.doFinal(plain);

            ByteBuffer packet = ByteBuffer.allocate(headerBytes.length + encrypted.length);
            packet.put(headerBytes);
            packet.put(encrypted);
            return packet.array();
        } catch (GeneralSecurityException e) {
            throw new StegoException("Encryption failed: " + safeCryptoMessage(e));
        } finally {
            if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);
            Arrays.fill(plain, (byte) 0);
        }
    }

    public static int headerBytesForMagic(byte[] magic) throws StegoException {
        if (magic == null || magic.length < MAGIC_BYTES) {
            throw new StegoException("Carrier is too small to contain a Studio message.");
        }
        byte[] first = Arrays.copyOf(magic, MAGIC_BYTES);
        if (Arrays.equals(first, MAGIC_V1)) return LEGACY_HEADER_BYTES;
        if (Arrays.equals(first, MAGIC_V2)) return ENCRYPTED_HEADER_BYTES;
        throw new StegoException("No Scarface Studio LSB message was found.");
    }

    public static Header parseHeader(byte[] header) throws StegoException {
        int headerSize = headerBytesForMagic(header);
        if (header.length < headerSize) throw new StegoException("Hidden packet header is incomplete.");

        ByteBuffer b = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[MAGIC_BYTES];
        b.get(magic);

        if (Arrays.equals(magic, MAGIC_V1)) {
            long payloadLength = Integer.toUnsignedLong(b.getInt());
            long storedCrc = Integer.toUnsignedLong(b.getInt());
            if (payloadLength > Integer.MAX_VALUE) throw new StegoException("Hidden message length is too large.");
            return Header.legacy((int) payloadLength, storedCrc);
        }

        long cipherLength = Integer.toUnsignedLong(b.getInt());
        long iterationsUnsigned = Integer.toUnsignedLong(b.getInt());
        if (cipherLength < GCM_TAG_BYTES || cipherLength > Integer.MAX_VALUE) {
            throw new StegoException("Encrypted payload length is invalid.");
        }
        if (iterationsUnsigned < 10_000L || iterationsUnsigned > 5_000_000L) {
            throw new StegoException("Encrypted packet has an invalid key-derivation setting.");
        }
        byte[] salt = new byte[SALT_BYTES];
        byte[] nonce = new byte[NONCE_BYTES];
        b.get(salt);
        b.get(nonce);
        return Header.encrypted((int) cipherLength, (int) iterationsUnsigned, salt, nonce);
    }

    public static Decoded decodePacket(byte[] packet, char[] password) throws StegoException {
        if (packet.length < MAGIC_BYTES) throw new StegoException("Hidden packet is incomplete.");
        int headerSize = headerBytesForMagic(packet);
        if (packet.length < headerSize) throw new StegoException("Hidden packet header is incomplete.");
        Header h = parseHeader(Arrays.copyOf(packet, headerSize));
        long required = (long) h.headerBytes + h.payloadLength;
        if (required > packet.length) throw new StegoException("Hidden packet is truncated.");

        if (!h.encrypted) {
            byte[] payload = Arrays.copyOfRange(packet, h.headerBytes, h.headerBytes + h.payloadLength);
            CRC32 crc = new CRC32();
            crc.update(payload);
            String text = new String(payload, StandardCharsets.UTF_8);
            return new Decoded(text, payload.length, crc.getValue() == h.storedCrc, false, "SCSTEG01");
        }

        if (password == null || password.length == 0) {
            throw new StegoException("This Studio message is encrypted. Enter its password to decrypt it.");
        }

        byte[] keyBytes = null;
        byte[] plain = null;
        try {
            keyBytes = deriveKey(password, h.salt, h.iterations);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new GCMParameterSpec(128, h.nonce));
            byte[] aad = Arrays.copyOf(packet, h.headerBytes);
            cipher.updateAAD(aad);
            byte[] ciphertext = Arrays.copyOfRange(packet, h.headerBytes, h.headerBytes + h.payloadLength);
            plain = cipher.doFinal(ciphertext);
            String text = new String(plain, StandardCharsets.UTF_8);
            return new Decoded(text, plain.length, true, true, "SCSTEG02");
        } catch (AEADBadTagException badTag) {
            throw new StegoException("Wrong password or encrypted data was modified.");
        } catch (GeneralSecurityException e) {
            throw new StegoException("Decryption failed: " + safeCryptoMessage(e));
        } finally {
            if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);
            if (plain != null) Arrays.fill(plain, (byte) 0);
        }
    }

    /** Legacy convenience overload. */
    public static Decoded decodePacket(byte[] packet) throws StegoException {
        return decodePacket(packet, new char[0]);
    }

    private static byte[] deriveKey(char[] password, byte[] salt, int iterations) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static String safeCryptoMessage(Exception e) {
        String m = e.getMessage();
        return (m == null || m.trim().isEmpty()) ? e.getClass().getSimpleName() : m;
    }

    public static final class Header {
        public final int headerBytes;
        public final int payloadLength;
        public final long storedCrc;
        public final boolean encrypted;
        public final int iterations;
        public final byte[] salt;
        public final byte[] nonce;

        private Header(int headerBytes, int payloadLength, long storedCrc, boolean encrypted,
                       int iterations, byte[] salt, byte[] nonce) {
            this.headerBytes = headerBytes;
            this.payloadLength = payloadLength;
            this.storedCrc = storedCrc;
            this.encrypted = encrypted;
            this.iterations = iterations;
            this.salt = salt;
            this.nonce = nonce;
        }

        static Header legacy(int payloadLength, long storedCrc) {
            return new Header(LEGACY_HEADER_BYTES, payloadLength, storedCrc, false, 0, null, null);
        }

        static Header encrypted(int payloadLength, int iterations, byte[] salt, byte[] nonce) {
            return new Header(ENCRYPTED_HEADER_BYTES, payloadLength, 0L, true, iterations, salt, nonce);
        }
    }

    public static final class Decoded {
        public final String text;
        public final int payloadBytes;
        public final boolean integrityValid;
        public final boolean encrypted;
        public final String format;

        Decoded(String text, int payloadBytes, boolean integrityValid, boolean encrypted, String format) {
            this.text = text;
            this.payloadBytes = payloadBytes;
            this.integrityValid = integrityValid;
            this.encrypted = encrypted;
            this.format = format;
        }
    }

    public static final class StegoException extends Exception {
        public StegoException(String message) { super(message); }
    }
}
