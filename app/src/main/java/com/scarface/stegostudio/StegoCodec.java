package com.scarface.stegostudio;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;

import java.io.InputStream;
import java.io.OutputStream;

/** RGB-LSB codec supporting legacy SCSTEG01 and encrypted SCSTEG02 packets. */
public final class StegoCodec {
    private StegoCodec() {}

    public static Bitmap decodeBitmap(InputStream in) throws Exception {
        Bitmap src = BitmapFactory.decodeStream(in);
        if (src == null) throw new Exception("Could not decode image.");
        Bitmap bmp = src.copy(Bitmap.Config.ARGB_8888, true);
        if (bmp == null) throw new Exception("Could not create editable image buffer.");
        return bmp;
    }

    /** Raw number of packet bytes available through RGB LSBs. */
    public static int capacityBytes(Bitmap bmp) {
        long channels = (long) bmp.getWidth() * bmp.getHeight() * 3L;
        return (int) Math.min(Integer.MAX_VALUE, channels / 8L);
    }

    public static int maxMessageBytes(Bitmap bmp, boolean encrypted) {
        int overhead = encrypted
                ? StegoPacket.ENCRYPTED_HEADER_BYTES + StegoPacket.GCM_TAG_BYTES
                : StegoPacket.LEGACY_HEADER_BYTES;
        return Math.max(0, capacityBytes(bmp) - overhead);
    }

    public static int encode(Bitmap bmp, String message, char[] password, boolean encrypted, OutputStream output) throws Exception {
        if (message.isEmpty()) throw new Exception("Enter a message before encoding.");
        byte[] packet = encrypted
                ? StegoPacket.buildEncrypted(message, password)
                : StegoPacket.buildLegacy(message);

        long requiredBits = (long) packet.length * 8L;
        long availableBits = (long) bmp.getWidth() * bmp.getHeight() * 3L;
        if (requiredBits > availableBits) {
            throw new Exception("Message packet needs " + packet.length + " bytes, but this image can store " + (availableBits / 8L) + " bytes.");
        }

        int w = bmp.getWidth(), h = bmp.getHeight();
        int[] pixels = new int[w * h];
        bmp.getPixels(pixels, 0, w, 0, 0, w, h);
        int bitIndex = 0;
        int required = packet.length * 8;
        for (int i = 0; i < pixels.length && bitIndex < required; i++) {
            int c = pixels[i];
            int a = Color.alpha(c), r = Color.red(c), g = Color.green(c), b = Color.blue(c);
            if (bitIndex < required) r = (r & 0xFE) | bit(packet, bitIndex++);
            if (bitIndex < required) g = (g & 0xFE) | bit(packet, bitIndex++);
            if (bitIndex < required) b = (b & 0xFE) | bit(packet, bitIndex++);
            pixels[i] = Color.argb(a, r, g, b);
        }
        bmp.setPixels(pixels, 0, w, 0, 0, w, h);
        if (!bmp.compress(Bitmap.CompressFormat.PNG, 100, output)) throw new Exception("Could not save PNG.");
        output.flush();
        return packet.length;
    }

    /** Legacy convenience overload: SCSTEG01. */
    public static int encode(Bitmap bmp, String message, OutputStream output) throws Exception {
        return encode(bmp, message, new char[0], false, output);
    }

    private static int bit(byte[] data, int bitIndex) {
        int value = data[bitIndex / 8] & 0xFF;
        return (value >> (7 - (bitIndex % 8))) & 1;
    }

    public static StegoPacket.Decoded decode(Bitmap bmp, char[] password) throws Exception {
        int capacity = capacityBytes(bmp);
        if (capacity < StegoPacket.MAGIC_BYTES) throw new Exception("Image is too small to contain a Studio message.");

        byte[] magic = readLsbBytes(bmp, StegoPacket.MAGIC_BYTES);
        int headerBytes = StegoPacket.headerBytesForMagic(magic);
        if (capacity < headerBytes) throw new Exception("Image is too small to contain the Studio packet header.");

        byte[] header = readLsbBytes(bmp, headerBytes);
        StegoPacket.Header h = StegoPacket.parseHeader(header);
        if ((long) h.headerBytes + h.payloadLength > capacity) {
            throw new Exception("The hidden header is damaged or reports an impossible size.");
        }

        byte[] packet = readLsbBytes(bmp, h.headerBytes + h.payloadLength);
        return StegoPacket.decodePacket(packet, password);
    }

    /** Legacy convenience overload. */
    public static StegoPacket.Decoded decode(Bitmap bmp) throws Exception {
        return decode(bmp, new char[0]);
    }

    private static byte[] readLsbBytes(Bitmap bmp, int byteCount) {
        byte[] out = new byte[byteCount];
        int w = bmp.getWidth(), h = bmp.getHeight();
        int[] pixels = new int[w * h];
        bmp.getPixels(pixels, 0, w, 0, 0, w, h);
        int bitIndex = 0, totalBits = byteCount * 8;
        for (int c : pixels) {
            int[] rgb = { Color.red(c), Color.green(c), Color.blue(c) };
            for (int channel : rgb) {
                if (bitIndex >= totalBits) return out;
                out[bitIndex / 8] |= (byte) ((channel & 1) << (7 - (bitIndex % 8)));
                bitIndex++;
            }
        }
        return out;
    }
}
