package com.scarface.stegostudio;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.zip.CRC32;

public final class Forensics {
    private Forensics() {}

    public enum Severity { INFO, NOTICE, WARNING, CRITICAL }

    public static final class Finding {
        public final Severity severity;
        public final String title;
        public final String detail;
        public final Integer offset;
        public Finding(Severity severity, String title, String detail, Integer offset) {
            this.severity = severity; this.title = title; this.detail = detail; this.offset = offset;
        }
    }

    public static final class Report {
        public String format = "Unknown";
        public int size;
        public int width = -1, height = -1;
        public String sha256 = "";
        public double entropy;
        public final List<Finding> findings = new ArrayList<>();
        public int appendedStart = -1, appendedEnd = -1;
        public final List<String> chunks = new ArrayList<>();
    }

    public static Report scan(byte[] data) throws Exception {
        Report r = new Report();
        r.size = data.length;
        r.format = detectFormat(data);
        r.sha256 = hex(MessageDigest.getInstance("SHA-256").digest(data));
        r.entropy = entropy(data);
        Integer logicalEnd = null;
        if ("PNG".equals(r.format)) logicalEnd = pngChunks(data, r);
        else if ("JPEG".equals(r.format)) logicalEnd = jpegEnd(data);
        else if ("WAV".equals(r.format)) logicalEnd = wavChunks(data, r);

        if (logicalEnd != null && logicalEnd < data.length) {
            int extra = data.length - logicalEnd;
            r.appendedStart = logicalEnd; r.appendedEnd = data.length;
            r.findings.add(new Finding(Severity.CRITICAL, "Data appended after image end",
                    extra + " trailing bytes are not part of the decoded image. They can be safely exported for analysis.", logicalEnd));
        }

        Object[][] signatures = new Object[][]{
                {new byte[]{'M','Z'}, "Windows executable header", "Possible PE/DOS executable data"},
                {new byte[]{0x7f,'E','L','F'}, "Linux executable header", "Possible ELF executable data"},
                {new byte[]{'P','K',3,4}, "ZIP/container header", "ZIP, APK, DOCX, JAR, or another container"},
                {new byte[]{'R','a','r','!',0x1a,7}, "RAR archive header", "Possible embedded RAR archive"},
                {new byte[]{'7','z',(byte)0xbc,(byte)0xaf,0x27,0x1c}, "7-Zip archive header", "Possible embedded 7-Zip archive"},
                {new byte[]{'%','P','D','F','-'}, "PDF header", "Possible embedded PDF document"},
                {new byte[]{'#','!','/','b','i','n','/'}, "Shell script marker", "Possible embedded Unix shell script"},
                {new byte[]{'p','o','w','e','r','s','h','e','l','l'}, "PowerShell text", "PowerShell command text was found"}
        };
        int scanStart = "PNG".equals(r.format) ? 8 : ("JPEG".equals(r.format) ? 3 : ("WAV".equals(r.format) ? 12 : 0));
        int[] wavData = "WAV".equals(r.format) ? wavDataRange(data) : null;
        for (Object[] sig : signatures) {
            byte[] needle = (byte[]) sig[0]; String title = (String) sig[1]; String detail = (String) sig[2];
            int count = 0;
            for (int i = scanStart; i <= data.length - needle.length && count < 8; i++) {
                // Raw PCM naturally contains arbitrary byte pairs; treating those as file signatures
                // creates severe false positives. Scan WAV container/chunk metadata and trailing data,
                // but skip the sample payload itself.
                if (wavData != null && i >= wavData[0] && i < wavData[1]) {
                    i = wavData[1] - 1;
                    continue;
                }
                if (matches(data, i, needle)) {
                    Severity sev = (title.contains("executable") || title.contains("script")) ? Severity.CRITICAL : Severity.WARNING;
                    r.findings.add(new Finding(sev, title, detail + " at file offset 0x" + Integer.toHexString(i).toUpperCase(Locale.ROOT) + ". Signature detection is an indicator, not a malware verdict.", i));
                    count++;
                }
            }
        }
        if (r.entropy > 7.85) {
            r.findings.add(new Finding(Severity.NOTICE, "Very high byte entropy",
                    String.format(Locale.US, "Entropy is %.3f/8.000. Compression can cause this normally, but encrypted or packed content can look similar.", r.entropy), null));
        }
        if (r.findings.isEmpty()) {
            r.findings.add(new Finding(Severity.INFO, "No obvious embedded payload indicators",
                    "Structural and signature checks found no immediate concerns. This is not a guarantee that the image is harmless.", null));
        }
        r.findings.sort(Comparator.comparing((Finding f) -> f.severity).reversed());
        return r;
    }

    private static String detectFormat(byte[] d) {
        if (starts(d, new byte[]{(byte)0x89,'P','N','G',13,10,26,10})) return "PNG";
        if (starts(d, new byte[]{(byte)0xff,(byte)0xd8,(byte)0xff})) return "JPEG";
        if (starts(d, "GIF87a".getBytes()) || starts(d, "GIF89a".getBytes())) return "GIF";
        if (starts(d, new byte[]{'B','M'})) return "BMP";
        if (d.length >= 12 && starts(d, "RIFF".getBytes()) && new String(d, 8, 4).equals("WEBP")) return "WebP";
        if (d.length >= 12 && starts(d, "RIFF".getBytes()) && new String(d, 8, 4).equals("WAVE")) return "WAV";
        return "Unknown";
    }

    private static Integer pngChunks(byte[] d, Report r) {
        byte[] png = new byte[]{(byte)0x89,'P','N','G',13,10,26,10};
        if (!starts(d, png)) return null;
        int pos = 8;
        while (pos + 12 <= d.length) {
            long lenLong = Integer.toUnsignedLong(ByteBuffer.wrap(d, pos, 4).order(ByteOrder.BIG_ENDIAN).getInt());
            if (lenLong > Integer.MAX_VALUE) return null;
            int len = (int) lenLong;
            long endLong = (long) pos + 12L + len;
            if (endLong > d.length) {
                r.findings.add(new Finding(Severity.CRITICAL, "Malformed PNG chunk", "Chunk at 0x" + Integer.toHexString(pos).toUpperCase(Locale.ROOT) + " extends beyond end of file.", pos));
                return null;
            }
            String kind = new String(d, pos + 4, 4);
            long stored = Integer.toUnsignedLong(ByteBuffer.wrap(d, pos + 8 + len, 4).order(ByteOrder.BIG_ENDIAN).getInt());
            CRC32 crc = new CRC32(); crc.update(d, pos + 4, 4 + len);
            r.chunks.add(String.format(Locale.US, "%-4s  %9d bytes  @ 0x%08X", kind, len, pos));
            if (stored != crc.getValue()) r.findings.add(new Finding(Severity.WARNING, "Invalid " + kind + " chunk CRC", "Chunk contents may be damaged or deliberately modified.", pos));
            if ((kind.equals("tEXt") || kind.equals("zTXt") || kind.equals("iTXt")) && len > 16384)
                r.findings.add(new Finding(Severity.WARNING, "Oversized " + kind + " metadata", "Text metadata is unusually large (" + len + " bytes).", pos));
            int end = (int) endLong;
            if (kind.equals("IEND")) return end;
            pos = end;
        }
        return null;
    }



    private static int[] wavDataRange(byte[] d) {
        if (d.length < 12 || !starts(d, "RIFF".getBytes()) || !new String(d, 8, 4).equals("WAVE")) return null;
        long logicalEndLong = Math.min((long)d.length, 8L + Integer.toUnsignedLong(ByteBuffer.wrap(d, 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt()));
        int logicalEnd = (int)Math.min(Integer.MAX_VALUE, logicalEndLong);
        int pos = 12;
        while (pos + 8 <= logicalEnd) {
            long lenLong = Integer.toUnsignedLong(ByteBuffer.wrap(d, pos + 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
            if (lenLong > Integer.MAX_VALUE) return null;
            int len = (int)lenLong;
            long payloadEnd = (long)pos + 8L + len;
            if (payloadEnd > logicalEnd || payloadEnd > d.length) return null;
            if (d[pos]=='d' && d[pos+1]=='a' && d[pos+2]=='t' && d[pos+3]=='a') return new int[]{pos+8, (int)payloadEnd};
            long next = payloadEnd + (len & 1);
            if (next <= pos || next > Integer.MAX_VALUE) return null;
            pos=(int)next;
        }
        return null;
    }

    private static Integer wavChunks(byte[] d, Report r) {
        if (d.length < 12 || !starts(d, "RIFF".getBytes()) || !new String(d, 8, 4).equals("WAVE")) return null;
        long riffSize = Integer.toUnsignedLong(ByteBuffer.wrap(d, 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
        long logicalEndLong = 8L + riffSize;
        if (logicalEndLong > d.length) {
            r.findings.add(new Finding(Severity.CRITICAL, "Truncated RIFF/WAV container",
                    "The RIFF header declares " + logicalEndLong + " bytes, but the file contains only " + d.length + ".", 4));
            logicalEndLong = d.length;
        }
        int logicalEnd = (int)Math.min(Integer.MAX_VALUE, logicalEndLong);
        int pos = 12;
        boolean foundFmt = false, foundData = false;
        while (pos + 8 <= logicalEnd) {
            String kind = new String(d, pos, 4);
            long lenLong = Integer.toUnsignedLong(ByteBuffer.wrap(d, pos + 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
            if (lenLong > Integer.MAX_VALUE) {
                r.findings.add(new Finding(Severity.CRITICAL, "Oversized WAV chunk", "Chunk size exceeds supported in-memory limits.", pos));
                return logicalEnd;
            }
            int len = (int)lenLong;
            long payloadEnd = (long)pos + 8L + len;
            if (payloadEnd > logicalEnd || payloadEnd > d.length) {
                r.findings.add(new Finding(Severity.CRITICAL, "Malformed WAV chunk",
                        "Chunk " + kind + " at 0x" + Integer.toHexString(pos).toUpperCase(Locale.ROOT) + " extends beyond the RIFF container.", pos));
                return logicalEnd;
            }
            r.chunks.add(String.format(Locale.US, "%-4s  %9d bytes  @ 0x%08X", kind, len, pos));
            if ("fmt ".equals(kind)) foundFmt = true;
            if ("data".equals(kind)) foundData = true;
            long next = payloadEnd + (len & 1);
            if (next <= pos || next > Integer.MAX_VALUE) break;
            pos = (int)next;
        }
        if (!foundFmt) r.findings.add(new Finding(Severity.WARNING, "WAV fmt chunk missing", "Audio format metadata was not found.", null));
        if (!foundData) r.findings.add(new Finding(Severity.WARNING, "WAV data chunk missing", "PCM/audio sample data was not found.", null));
        return logicalEnd;
    }

    private static Integer jpegEnd(byte[] d) {
        for (int i = d.length - 2; i >= 0; i--) if ((d[i] & 0xff) == 0xff && (d[i+1] & 0xff) == 0xd9) return i + 2;
        return null;
    }

    public static String hexdump(byte[] d, int start, int rows) {
        StringBuilder out = new StringBuilder();
        int end = Math.min(d.length, start + rows * 16);
        for (int off = start; off < end; off += 16) {
            int rowEnd = Math.min(end, off + 16);
            out.append(String.format(Locale.US, "%08X  ", off));
            for (int i = 0; i < 16; i++) {
                int idx = off + i;
                if (idx < rowEnd) out.append(String.format(Locale.US, "%02X ", d[idx] & 0xff)); else out.append("   ");
                if (i == 7) out.append(' ');
            }
            out.append(" | ");
            for (int i = off; i < rowEnd; i++) {
                int b = d[i] & 0xff;
                out.append(b >= 32 && b <= 126 ? (char)b : '·');
            }
            out.append('\n');
        }
        return out.toString();
    }

    private static double entropy(byte[] d) {
        if (d.length == 0) return 0;
        int[] counts = new int[256]; for (byte b : d) counts[b & 0xff]++;
        double sum = 0;
        for (int n : counts) if (n > 0) { double p = n / (double)d.length; sum -= p * (Math.log(p) / Math.log(2)); }
        return sum;
    }

    private static boolean starts(byte[] d, byte[] n) { return d.length >= n.length && matches(d, 0, n); }
    private static boolean matches(byte[] d, int p, byte[] n) {
        if (p < 0 || p + n.length > d.length) return false;
        for (int i = 0; i < n.length; i++) if (d[p+i] != n[i]) return false;
        return true;
    }
    private static String hex(byte[] d) { StringBuilder s = new StringBuilder(d.length * 2); for (byte b : d) s.append(String.format(Locale.US, "%02x", b & 0xff)); return s.toString(); }
}
