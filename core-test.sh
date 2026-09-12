#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

JAVAC="${JAVAC:-javac}"
JAVA="${JAVA:-java}"

mkdir -p "$TMP/classes"
"$JAVAC" -d "$TMP/classes" \
  "$HERE/app/src/main/java/com/scarface/stegostudio/StegoPacket.java" \
  "$HERE/app/src/main/java/com/scarface/stegostudio/WavStegoCodec.java" \
  "$HERE/app/src/main/java/com/scarface/stegostudio/Forensics.java"

cat > "$TMP/CoreTest.java" <<'JAVA'
import com.scarface.stegostudio.*;
import java.nio.*;
import java.util.*;

public class CoreTest {
    static byte[] wav(int rate, int channels, int bits, int frames) throws Exception {
        int bytesPerSample=bits/8, block=channels*bytesPerSample, data=frames*block;
        ByteBuffer b=ByteBuffer.allocate(44+data).order(ByteOrder.LITTLE_ENDIAN);
        b.put("RIFF".getBytes("US-ASCII")); b.putInt(36+data); b.put("WAVE".getBytes("US-ASCII"));
        b.put("fmt ".getBytes("US-ASCII")); b.putInt(16); b.putShort((short)1); b.putShort((short)channels);
        b.putInt(rate); b.putInt(rate*block); b.putShort((short)block); b.putShort((short)bits);
        b.put("data".getBytes("US-ASCII")); b.putInt(data);
        Random r=new Random(312); while(b.hasRemaining()) b.put((byte)r.nextInt(256));
        return b.array();
    }

    public static void main(String[] args) throws Exception {
        byte[] original=wav(44100,2,16,44100);
        WavStegoCodec.Info info=WavStegoCodec.parse(original);
        if(!info.supportedPcm || info.capacityBytes < 1000) throw new RuntimeException("WAV parse/capacity failed");

        String message="Scarface audio stego round-trip 🔐";
        char[] password="correct horse battery staple".toCharArray();
        WavStegoCodec.Result encrypted=WavStegoCodec.encode(original,message,password,true);
        StegoPacket.Decoded decoded=WavStegoCodec.decode(encrypted.wav,password);
        if(!message.equals(decoded.text) || !decoded.encrypted) throw new RuntimeException("encrypted WAV round-trip failed");
        if(encrypted.wav.length != original.length) throw new RuntimeException("WAV length changed");

        boolean wrongRejected=false;
        try { WavStegoCodec.decode(encrypted.wav,"definitely-wrong".toCharArray()); }
        catch(Exception expected) { wrongRejected=true; }
        if(!wrongRejected) throw new RuntimeException("wrong password was accepted");

        WavStegoCodec.Result legacy=WavStegoCodec.encode(original,"legacy audio",new char[0],false);
        StegoPacket.Decoded legacyDecoded=WavStegoCodec.decode(legacy.wav,new char[0]);
        if(!"legacy audio".equals(legacyDecoded.text) || legacyDecoded.encrypted || !legacyDecoded.integrityValid)
            throw new RuntimeException("legacy WAV round-trip failed");

        Forensics.Report report=Forensics.scan(original);
        if(!"WAV".equals(report.format) || report.chunks.size() < 2) throw new RuntimeException("WAV forensic parse failed");

        System.out.println("PASS: encrypted WAV round-trip");
        System.out.println("PASS: wrong-password rejection");
        System.out.println("PASS: legacy WAV round-trip + CRC");
        System.out.println("PASS: RIFF/WAV forensic chunk scan");
        System.out.println("Capacity: " + info.capacityBytes + " packet bytes");
    }
}
JAVA

"$JAVAC" -cp "$TMP/classes" -d "$TMP/classes" "$TMP/CoreTest.java"
"$JAVA" -cp "$TMP/classes" CoreTest
