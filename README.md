# Scarface Stego Studio Mobile v0.3.0

Native Android steganography and media-forensics workstation. v0.3.0 keeps the existing PNG workflow and adds **encrypted message hiding/revealing in uncompressed PCM WAV audio** inside the same app.

## What is new in v0.3.0

- **OPEN MEDIA** now accepts images and WAV files.
- PCM WAV steganography for **8 / 16 / 24 / 32-bit integer PCM**.
- One hidden bit is stored in the least-significant bit of each PCM sample's least-significant byte.
- Existing **SCSTEG02 AES-256-GCM** encryption is reused for both PNG and WAV carriers.
- Legacy **SCSTEG01** packets can also be placed in/revealed from WAV when encryption is intentionally disabled.
- WAV dashboard shows sample rate, channels, bit depth, duration, and stego capacity.
- RIFF/WAV chunk inspection was added to the forensic inspector.
- WAV signature scanning skips raw PCM sample bytes to avoid obvious false positives from arbitrary audio data.
- MP3/AAC and compressed WAV are inspect-only/unsupported for embedding by design because lossy transcoding can destroy simple LSB steganography.

## Existing features retained

- Lossless PNG RGB-LSB hide/reveal.
- PBKDF2-HMAC-SHA256 (210,000 iterations) + AES-256-GCM authenticated encryption.
- Fresh random salt and nonce for each encrypted message.
- Wrong-password/tamper rejection.
- SHA-256, entropy, media/container checks, appended-payload detection, file-signature indicators, and read-only hex/ASCII Binary Lab.
- No `INTERNET` permission. Processing is on-device.

## Build on Kali / Linux

The build script auto-detects the Android SDK and a compatible JDK and can bootstrap Gradle 8.11.1.

```bash
cd ~/Downloads
unzip Scarface-Stego-Studio-Mobile-v0.3.0.zip
cd Scarface-Stego-Studio-Mobile-v0.3.0
chmod +x build.sh core-test.sh
./core-test.sh
./build.sh
```

Expected APK:

```text
app/build/outputs/apk/debug/app-debug.apk
```

Install over the existing app while the phone is visible to ADB:

```bash
"$HOME/Android/Sdk/platform-tools/adb" install -r \
"$HOME/Downloads/Scarface-Stego-Studio-Mobile-v0.3.0/app/build/outputs/apk/debug/app-debug.apk"
```

## Using WAV mode

1. Tap **OPEN MEDIA** and choose an uncompressed PCM `.wav` file.
2. Confirm the dashboard says **WAV PCM** and **LSB READY**.
3. Open **HIDE**, type a message, and keep encryption enabled.
4. Enter/confirm a password and save the output WAV.
5. Re-open that WAV, open **REVEAL**, enter the password, and decrypt.

Avoid converting the resulting WAV to MP3/AAC or sending it through a service that recompresses audio if you need the hidden packet to survive.

## Scope

This project is intended for legitimate privacy, education, forensic research, and files you own or are authorised to inspect. Extracted or suspicious content is never executed by the app.
