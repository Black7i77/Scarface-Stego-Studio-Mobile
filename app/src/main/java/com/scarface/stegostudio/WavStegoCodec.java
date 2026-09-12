package com.scarface.stegostudio;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Lossless steganography for RIFF/WAVE carriers.
 *
 * v0.3.0 deliberately supports uncompressed integer PCM WAV only (format 1,
 * 8/16/24/32-bit). One packet bit is stored in the least-significant bit of
 * each PCM sample's least-significant byte. RIFF headers/chunk layout are
 * preserved byte-for-byte; only sample LSBs inside the data chunk change.
 */
public final class WavStegoCodec {
    private WavStegoCodec() {}

    public static boolean looksLikeWav(byte[] d) {
        return d != null && d.length >= 12
                && asciiEquals(d, 0, "RIFF")
                && asciiEquals(d, 8, "WAVE");
    }

    public static Info parse(byte[] wav) throws Exception {
        if (!looksLikeWav(wav)) throw new Exception("Not a RIFF/WAVE file.");

        long declaredEndLong = 8L + u32le(wav, 4);
        int scanEnd = (int) Math.min((long) wav.length, Math.max(12L, declaredEndLong));

        int audioFormat = -1;
        int channels = -1;
        long sampleRate = -1;
        int blockAlign = -1;
        int bitsPerSample = -1;
        int dataOffset = -1;
        int dataSize = -1;

        int pos = 12;
        while (pos + 8 <= scanEnd) {
            String id = new String(wav, pos, 4, StandardCharsets.US_ASCII);
            long sizeLong = u32le(wav, pos + 4);
            if (sizeLong > Integer.MAX_VALUE) throw new Exception("WAV chunk is too large for this device.");
            int size = (int) sizeLong;
            long payloadEndLong = (long) pos + 8L + size;
            if (payloadEndLong > wav.length || payloadEndLong > scanEnd) {
                throw new Exception("WAV chunk " + printableChunk(id) + " is truncated.");
            }
            int payload = pos + 8;

            if ("fmt ".equals(id) && size >= 16) {
                audioFormat = u16le(wav, payload);
                channels = u16le(wav, payload + 2);
                sampleRate = u32le(wav, payload + 4);
                blockAlign = u16le(wav, payload + 12);
                bitsPerSample = u16le(wav, payload + 14);
            } else if ("data".equals(id) && dataOffset < 0) {
                dataOffset = payload;
                dataSize = size;
            }

            long next = payloadEndLong + (size & 1); // RIFF chunks are word-aligned.
            if (next <= pos || next > Integer.MAX_VALUE) break;
            pos = (int) next;
        }

        if (audioFormat < 0) throw new Exception("WAV fmt chunk was not found.");
        if (dataOffset < 0) throw new Exception("WAV data chunk was not found.");
        if (channels <= 0 || sampleRate <= 0 || blockAlign <= 0 || bitsPerSample <= 0) {
            throw new Exception("WAV format metadata is invalid.");
        }

        int bytesPerSample = (bitsPerSample % 8 == 0) ? bitsPerSample / 8 : 0;
        boolean supported = audioFormat == 1
                && (bitsPerSample == 8 || bitsPerSample == 16 || bitsPerSample == 24 || bitsPerSample == 32)
                && bytesPerSample > 0
                && blockAlign == channels * bytesPerSample;

        long sampleCount = supported ? dataSize / (long) bytesPerSample : 0L;
        long capacity = supported ? sampleCount / 8L : 0L;
        long frameCount = blockAlign > 0 ? dataSize / (long) blockAlign : 0L;
        double duration = sampleRate > 0 ? frameCount / (double) sampleRate : 0.0;

        return new Info(audioFormat, channels, sampleRate, blockAlign, bitsPerSample,
                bytesPerSample, dataOffset, dataSize, frameCount, sampleCount,
                (int) Math.min(Integer.MAX_VALUE, capacity), duration, supported);
    }

    public static Result encode(byte[] wav, String message, char[] password, boolean encrypted) throws Exception {
        if (message == null || message.isEmpty()) throw new Exception("Enter a message before encoding.");
        Info info = parse(wav);
        requireSupported(info);

        byte[] packet = encrypted
                ? StegoPacket.buildEncrypted(message, password)
                : StegoPacket.buildLegacy(message);
        if (packet.length > info.capacityBytes) {
            throw new Exception("Message packet needs " + packet.length + " bytes, but this WAV can store " + info.capacityBytes + " bytes.");
        }

        byte[] out = Arrays.copyOf(wav, wav.length);
        int totalBits = packet.length * 8;
        for (int bitIndex = 0; bitIndex < totalBits; bitIndex++) {
            long sampleIndex = bitIndex;
            long bytePosLong = (long) info.dataOffset + sampleIndex * info.bytesPerSample;
            if (bytePosLong < info.dataOffset || bytePosLong >= (long) info.dataOffset + info.dataSize) {
                throw new Exception("WAV sample map ended unexpectedly.");
            }
            int bytePos = (int) bytePosLong;
            int bit = packetBit(packet, bitIndex);
            out[bytePos] = (byte) ((out[bytePos] & 0xFE) | bit);
        }
        return new Result(out, packet.length, info);
    }

    public static StegoPacket.Decoded decode(byte[] wav, char[] password) throws Exception {
        Info info = parse(wav);
        requireSupported(info);
        if (info.capacityBytes < StegoPacket.MAGIC_BYTES) {
            throw new Exception("WAV is too short to contain a Studio message.");
        }

        byte[] magic = readLsbBytes(wav, info, StegoPacket.MAGIC_BYTES);
        int headerBytes = StegoPacket.headerBytesForMagic(magic);
        if (info.capacityBytes < headerBytes) throw new Exception("WAV is too short to contain the Studio packet header.");

        byte[] header = readLsbBytes(wav, info, headerBytes);
        StegoPacket.Header h = StegoPacket.parseHeader(header);
        if ((long) h.headerBytes + h.payloadLength > info.capacityBytes) {
            throw new Exception("The hidden WAV packet header is damaged or reports an impossible size.");
        }

        byte[] packet = readLsbBytes(wav, info, h.headerBytes + h.payloadLength);
        return StegoPacket.decodePacket(packet, password);
    }

    public static int maxMessageBytes(Info info, boolean encrypted) {
        if (info == null || !info.supportedPcm) return 0;
        int overhead = encrypted
                ? StegoPacket.ENCRYPTED_HEADER_BYTES + StegoPacket.GCM_TAG_BYTES
                : StegoPacket.LEGACY_HEADER_BYTES;
        return Math.max(0, info.capacityBytes - overhead);
    }

    private static byte[] readLsbBytes(byte[] wav, Info info, int byteCount) throws Exception {
        if (byteCount < 0 || byteCount > info.capacityBytes) throw new Exception("Requested hidden WAV data exceeds carrier capacity.");
        byte[] out = new byte[byteCount];
        int totalBits = byteCount * 8;
        for (int bitIndex = 0; bitIndex < totalBits; bitIndex++) {
            long bytePosLong = (long) info.dataOffset + (long) bitIndex * info.bytesPerSample;
            if (bytePosLong >= (long) info.dataOffset + info.dataSize) throw new Exception("WAV sample data ended unexpectedly.");
            int bit = wav[(int) bytePosLong] & 1;
            out[bitIndex / 8] |= (byte) (bit << (7 - (bitIndex % 8)));
        }
        return out;
    }

    private static void requireSupported(Info info) throws Exception {
        if (!info.supportedPcm) {
            throw new Exception("Audio steganography currently supports uncompressed PCM WAV at 8, 16, 24, or 32 bits per sample. MP3/AAC and compressed WAV are intentionally not modified.");
        }
    }

    private static int packetBit(byte[] data, int bitIndex) {
        int value = data[bitIndex / 8] & 0xFF;
        return (value >> (7 - (bitIndex % 8))) & 1;
    }

    private static int u16le(byte[] d, int off) throws Exception {
        if (off < 0 || off + 2 > d.length) throw new Exception("WAV metadata is truncated.");
        return (d[off] & 0xFF) | ((d[off + 1] & 0xFF) << 8);
    }

    private static long u32le(byte[] d, int off) throws Exception {
        if (off < 0 || off + 4 > d.length) throw new Exception("WAV metadata is truncated.");
        return ((long) d[off] & 0xFF)
                | (((long) d[off + 1] & 0xFF) << 8)
                | (((long) d[off + 2] & 0xFF) << 16)
                | (((long) d[off + 3] & 0xFF) << 24);
    }

    private static boolean asciiEquals(byte[] d, int off, String s) {
        if (off < 0 || off + s.length() > d.length) return false;
        for (int i = 0; i < s.length(); i++) if ((byte) s.charAt(i) != d[off + i]) return false;
        return true;
    }

    private static String printableChunk(String id) {
        StringBuilder s = new StringBuilder(4);
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            s.append(c >= 32 && c <= 126 ? c : '?');
        }
        return s.toString();
    }

    public static final class Info {
        public final int audioFormat;
        public final int channels;
        public final long sampleRate;
        public final int blockAlign;
        public final int bitsPerSample;
        public final int bytesPerSample;
        public final int dataOffset;
        public final int dataSize;
        public final long frameCount;
        public final long sampleCount;
        public final int capacityBytes;
        public final double durationSeconds;
        public final boolean supportedPcm;

        Info(int audioFormat, int channels, long sampleRate, int blockAlign, int bitsPerSample,
             int bytesPerSample, int dataOffset, int dataSize, long frameCount, long sampleCount,
             int capacityBytes, double durationSeconds, boolean supportedPcm) {
            this.audioFormat = audioFormat;
            this.channels = channels;
            this.sampleRate = sampleRate;
            this.blockAlign = blockAlign;
            this.bitsPerSample = bitsPerSample;
            this.bytesPerSample = bytesPerSample;
            this.dataOffset = dataOffset;
            this.dataSize = dataSize;
            this.frameCount = frameCount;
            this.sampleCount = sampleCount;
            this.capacityBytes = capacityBytes;
            this.durationSeconds = durationSeconds;
            this.supportedPcm = supportedPcm;
        }
    }

    public static final class Result {
        public final byte[] wav;
        public final int packetBytes;
        public final Info info;
        Result(byte[] wav, int packetBytes, Info info) {
            this.wav = wav;
            this.packetBytes = packetBytes;
            this.info = info;
        }
    }
}
