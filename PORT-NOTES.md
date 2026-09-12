# v0.3.0 Port Notes

## Carrier architecture

The app now has two carrier backends sharing one packet/encryption layer:

- `StegoCodec.java` — bitmap RGB-LSB for images; output is lossless PNG.
- `WavStegoCodec.java` — PCM sample-LSB for RIFF/WAVE; WAV length/chunk layout is preserved.
- `StegoPacket.java` — carrier-independent SCSTEG01/SCSTEG02 packet creation, parsing, encryption, authentication, and decoding.

## WAV embedding

For supported integer PCM WAV:

- Parse RIFF + `fmt ` + `data` chunks.
- Accept WAVE format code 1 (PCM) and 8/16/24/32-bit samples.
- Require standard PCM block alignment.
- Use one sample for one hidden bit.
- For multi-byte samples, modify only the least-significant byte of the sample.
- Do not alter RIFF headers or resize the file.

Capacity is approximately `sample_count / 8` packet bytes before packet overhead.

## Compatibility

SCSTEG02 is unchanged from v0.2.0, so the cryptographic packet format remains stable. The *carrier* differs, but encryption/decryption semantics are the same.
