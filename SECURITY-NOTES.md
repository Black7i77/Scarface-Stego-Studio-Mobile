# Security Notes — v0.3.0

- AES-256-GCM provides confidentiality plus authentication for SCSTEG02 messages.
- PBKDF2-HMAC-SHA256 uses a fresh 16-byte salt and 210,000 iterations.
- AES-GCM uses a fresh 12-byte random nonce for each encrypted packet.
- The password is not stored in the carrier.
- Password character arrays are cleared where practical after operations.
- Audio steganography is **not** encryption by itself; encryption remains enabled by default.
- LSB steganography is fragile under lossy transcoding, resampling, normalization, editing, or platform recompression.
- MP3/AAC embedding is intentionally not implemented in this release.
- WAV embedding supports standard integer PCM only; compressed/float/extensible variants are not modified unless they are explicitly supported in a later release.
- The forensic signature scanner skips raw PCM sample bytes to reduce random signature false positives.
- The app does not execute extracted/discovered content and requests no `INTERNET` permission.
