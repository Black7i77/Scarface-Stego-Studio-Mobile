package com.scarface.stegostudio;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.database.Cursor;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private static final int BG = Color.rgb(7,10,14), PANEL = Color.rgb(14,19,25), CARD = Color.rgb(20,27,35);
    private static final int GREEN = Color.rgb(57,224,145), GOLD = Color.rgb(221,179,84), MUTED = Color.rgb(137,151,166);
    private static final int BLUE = Color.rgb(80,170,255), CRITICAL = Color.rgb(255,88,105), WHITE = Color.WHITE;
    private static final int REQ_OPEN = 10, REQ_SAVE_STEGO = 11, REQ_EXPORT = 12;

    private enum Page { DASHBOARD, INSPECT, HIDE, REVEAL, BINARY, ABOUT }
    private enum CarrierKind { NONE, IMAGE, WAV }
    private Page page = Page.DASHBOARD;
    private CarrierKind carrierKind = CarrierKind.NONE;
    private Uri selectedUri;
    private String selectedName = "No media selected";
    private byte[] selectedBytes = new byte[0];
    private Forensics.Report report;
    private WavStegoCodec.Info wavInfo;
    private long scanMs;
    private String message = "", revealed = "";
    private int binaryOffset = 0;
    private int exportStart = -1, exportEnd = -1;
    private boolean pendingEncrypt = true;
    private char[] pendingHidePassword = new char[0];

    private TextView fileLabel, statusLabel;
    private FrameLayout content;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(PANEL);
        getWindow().setNavigationBarColor(BG);
        setContentView(buildShell());
        showPage(Page.DASHBOARD);
    }

    @Override protected void onDestroy() { clearPendingPassword(); worker.shutdownNow(); super.onDestroy(); }

    private View buildShell() {
        LinearLayout root = column(BG);
        root.addView(buildHeader());
        root.addView(buildNav());
        content = new FrameLayout(this); content.setBackgroundColor(BG);
        root.addView(content, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private View buildHeader() {
        LinearLayout box = column(PANEL); box.setPadding(dp(18), dp(14), dp(18), dp(12));
        LinearLayout top = row(PANEL); top.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout names = column(PANEL);
        TextView brand = text("SCARFACE", 22, GREEN, true); names.addView(brand);
        TextView sub = text("S T E G O   S T U D I O   •   M O B I L E", 9, GOLD, true); names.addView(sub);
        top.addView(names, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button open = button("OPEN MEDIA", GREEN, BG); open.setOnClickListener(v -> openMedia()); top.addView(open);
        box.addView(top);
        fileLabel = text(selectedName, 13, WHITE, true); fileLabel.setPadding(0, dp(10), 0, 0); box.addView(fileLabel);
        statusLabel = text("Ready — analysis stays on this phone.", 11, MUTED, false); box.addView(statusLabel);
        return box;
    }

    private View buildNav() {
        HorizontalScrollView hsv = new HorizontalScrollView(this); hsv.setHorizontalScrollBarEnabled(false); hsv.setBackgroundColor(PANEL);
        LinearLayout nav = row(PANEL); nav.setPadding(dp(12), dp(4), dp(12), dp(10));
        Object[][] items = {{Page.DASHBOARD,"DASH"},{Page.INSPECT,"INSPECT"},{Page.HIDE,"HIDE"},{Page.REVEAL,"REVEAL"},{Page.BINARY,"BINARY"},{Page.ABOUT,"ABOUT"}};
        for (Object[] item : items) {
            Button b = button((String)item[1], Color.TRANSPARENT, MUTED);
            b.setTag(item[0]); b.setOnClickListener(v -> showPage((Page)v.getTag()));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, dp(40)); lp.setMargins(0,0,dp(7),0); nav.addView(b, lp);
        }
        hsv.addView(nav); return hsv;
    }

    private void showPage(Page p) {
        page = p; content.removeAllViews();
        View pageView;
        switch (p) {
            case INSPECT: pageView = inspectorPage(); break;
            case HIDE: pageView = hidePage(); break;
            case REVEAL: pageView = revealPage(); break;
            case BINARY: pageView = binaryPage(); break;
            case ABOUT: pageView = aboutPage(); break;
            default: pageView = dashboardPage();
        }
        content.addView(pageView);
    }

    private View page(String title, String subtitle, View body) {
        ScrollView scroll = new ScrollView(this); scroll.setFillViewport(true); scroll.setBackgroundColor(BG);
        LinearLayout base = column(BG); base.setPadding(dp(18), dp(20), dp(18), dp(30));
        base.addView(text(title, 27, WHITE, true)); base.addView(text(subtitle, 12, MUTED, false)); spacer(base, 16);
        base.addView(body); scroll.addView(base); return scroll;
    }

    private View dashboardPage() {
        LinearLayout body = column(BG);
        String fmt = report == null ? "—" : report.format;
        String size = report == null ? "—" : String.format(Locale.US, "%.2f MB", report.size / 1048576.0);
        Forensics.Severity sev = report == null ? Forensics.Severity.INFO : maxSeverity(report);
        String risk = report == null ? "READY" : severityName(sev);
        String capacity = report == null ? "—" : humanBytes(rawCarrierCapacity());
        body.addView(metricCard("MEDIA FORMAT", fmt, GREEN)); spacer(body, 9);
        body.addView(metricCard("FILE SIZE", size, GOLD)); spacer(body, 9);
        body.addView(metricCard("STEGO CAPACITY", capacity, GREEN)); spacer(body, 9);
        body.addView(metricCard("SCAN STATUS", risk, report == null ? BLUE : severityColor(sev))); spacer(body, 14);

        if (carrierKind == CarrierKind.WAV && wavInfo != null) {
            LinearLayout audio = card();
            audio.addView(text("PCM AUDIO PROFILE", 10, GOLD, true)); spacer(audio, 7);
            String support = wavInfo.supportedPcm ? "LSB READY" : "INSPECT ONLY";
            audio.addView(text(audioSummary() + "   •   " + support, 13, wavInfo.supportedPcm ? GREEN : GOLD, true));
            spacer(audio, 5);
            audio.addView(text("Audio mode changes only the least-significant bit of PCM samples; RIFF headers and other chunks are preserved.", 10, MUTED, false));
            body.addView(audio); spacer(body, 12);
        }

        LinearLayout pipe = card(); pipe.addView(text("FORENSIC PIPELINE", 10, GOLD, true)); spacer(pipe,8);
        pipe.addView(text("Structure → Metadata / chunks → Signatures → Trailing payloads → LSB format probe / decrypt", 15, WHITE, false)); spacer(pipe,7);
        pipe.addView(text("Signature results are indicators for investigation—not automatic proof of malware.", 11, MUTED, false)); body.addView(pipe);
        return page("Command Dashboard", "Inspect, reveal, and create image or PCM-WAV steganography from one private mobile workspace.", body);
    }

    private View inspectorPage() {
        LinearLayout body = column(BG);
        if (report == null) {
            LinearLayout c = card(); c.addView(text("Open an image or WAV file to begin forensic inspection.", 14, MUTED, false)); body.addView(c);
            return page("Forensic Inspector", "Structural checks, hashes, entropy, signatures, trailing data, and media chunk analysis.", body);
        }

        String mediaDetails = carrierKind == CarrierKind.WAV && wavInfo != null ? audioSummary() : dims();
        body.addView(text(report.format + "   •   " + mediaDetails + "   •   Entropy " + String.format(Locale.US,"%.3f",report.entropy) + "   •   " + scanMs + " ms", 11, WHITE, true)); spacer(body,10);
        LinearLayout sha = card(); sha.addView(text("SHA-256", 10, MUTED, true)); TextView hv=text(report.sha256,11,GREEN,false); hv.setTypeface(Typeface.MONOSPACE); hv.setTextIsSelectable(true); sha.addView(hv); body.addView(sha); spacer(body,10);

        if (carrierKind == CarrierKind.WAV && wavInfo != null) {
            LinearLayout a = card(); a.addView(text("WAV STEGO PROFILE", 10, GOLD, true)); spacer(a,6);
            a.addView(text("Raw packet capacity: " + humanBytes(wavInfo.capacityBytes) + "\nEncrypted message capacity: " + humanBytes(messageCapacity(true)) + "\nPCM support: " + (wavInfo.supportedPcm ? "Yes" : "No — inspection only"), 11, WHITE, false));
            body.addView(a); spacer(body,10);
        }

        if (report.appendedStart >= 0) {
            Button export = button("EXPORT APPENDED BYTES SAFELY", Color.rgb(98,43,51), WHITE);
            export.setOnClickListener(v -> beginExport(report.appendedStart, report.appendedEnd)); body.addView(export); spacer(body,10);
        }
        for (Forensics.Finding f : report.findings) {
            LinearLayout c = card();
            String off = f.offset == null ? "" : "   0x" + Integer.toHexString(f.offset).toUpperCase(Locale.ROOT);
            c.addView(text(severityName(f.severity) + "   " + f.title + off, 12, severityColor(f.severity), true));
            c.addView(text(f.detail, 11, MUTED, false)); body.addView(c); spacer(body,8);
        }
        if (!report.chunks.isEmpty()) {
            LinearLayout c = card(); c.addView(text(carrierKind == CarrierKind.WAV ? "RIFF/WAV CHUNK MAP" : "PNG CHUNK MAP", 10, GOLD, true)); spacer(c,6);
            TextView map = text(String.join("\n", report.chunks), 10, WHITE, false); map.setTypeface(Typeface.MONOSPACE); map.setTextIsSelectable(true); c.addView(map); body.addView(c);
        }
        return page("Forensic Inspector", "Structural checks, hashes, entropy, signatures, trailing data, and media chunk analysis.", body);
    }

    private View hidePage() {
        LinearLayout body = column(BG); LinearLayout c = card();

        CheckBox encryptBox = new CheckBox(this);
        encryptBox.setText("Encrypt with AES-256-GCM (recommended)");
        encryptBox.setTextColor(GREEN);
        encryptBox.setTextSize(12);
        encryptBox.setChecked(true);
        c.addView(encryptBox);

        String target = carrierKind == CarrierKind.WAV
                ? "The encrypted SCSTEG02 packet is written into PCM sample LSBs. Lossy transcoding to MP3/AAC can destroy hidden data."
                : "The encrypted SCSTEG02 packet is written into RGB pixel LSBs and saved as a lossless PNG.";
        TextView cryptoNote = text(
                "SCSTEG02 uses PBKDF2-HMAC-SHA256 + AES-256-GCM. The password is never stored in the carrier. " + target +
                " Turn encryption off only when you need legacy SCSTEG01 compatibility.",
                10, MUTED, false);
        c.addView(cryptoNote); spacer(c,10);

        TextView counter = text("", 10, MUTED, false); c.addView(counter);
        EditText edit = edit(message, "Type the private message you want to place inside this carrier…", true);
        c.addView(edit, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(190)));
        spacer(c,10);

        EditText pass = passwordEdit("Encryption password (8+ characters)");
        EditText confirm = passwordEdit("Confirm encryption password");
        c.addView(pass); spacer(c,8); c.addView(confirm);

        Runnable refreshCounter = () -> {
            boolean encrypted = encryptBox.isChecked();
            int used = edit.getText().toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            int cap = messageCapacity(encrypted);
            counter.setText(used + " / " + cap + " message bytes" + (encrypted ? "  •  encrypted" : "  •  legacy") + "  •  " + carrierName());
            pass.setEnabled(encrypted);
            confirm.setEnabled(encrypted);
            pass.setAlpha(encrypted ? 1.0f : 0.45f);
            confirm.setAlpha(encrypted ? 1.0f : 0.45f);
        };
        edit.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) { refreshCounter.run(); }
            @Override public void afterTextChanged(Editable s) {}
        });
        encryptBox.setOnCheckedChangeListener((buttonView, isChecked) -> refreshCounter.run());
        refreshCounter.run();

        spacer(c,12);
        String saveKind = carrierKind == CarrierKind.WAV ? "WAV" : "PNG";
        Button encode = button("ENCRYPT / ENCODE & SAVE " + saveKind, GREEN, BG);
        encode.setEnabled(canEncodeSelected());
        encode.setOnClickListener(v -> {
            message = edit.getText().toString();
            boolean encrypted = encryptBox.isChecked();
            if (message.isEmpty()) { toast("Enter a message first."); return; }
            if (!canEncodeSelected()) { toast("Open a supported image or uncompressed PCM WAV first."); return; }

            int msgBytes = message.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            if (msgBytes > messageCapacity(encrypted)) {
                toast("Message is too large for this carrier.");
                return;
            }

            clearPendingPassword();
            pendingEncrypt = encrypted;
            if (encrypted) {
                String p1 = pass.getText().toString();
                String p2 = confirm.getText().toString();
                if (p1.length() < 8) { toast("Use a password of at least 8 characters."); return; }
                if (!p1.equals(p2)) { toast("Passwords do not match."); return; }
                pendingHidePassword = p1.toCharArray();
            }
            saveStego();
        });
        c.addView(encode); body.addView(c);
        String subtitle = carrierKind == CarrierKind.WAV
                ? "Authenticated encryption, then sample-LSB embedding into uncompressed PCM WAV audio."
                : "Authenticated encryption, then RGB-LSB embedding into a lossless PNG image.";
        return page("Hide a Message", subtitle, body);
    }

    private View revealPage() {
        LinearLayout body = column(BG); LinearLayout c = card();
        c.addView(text("SCSTEG02 carriers require their password. Legacy SCSTEG01 carriers can still be revealed without one. The same packet format works in PNG images and PCM WAV audio.", 10, MUTED, false));
        spacer(c,10);
        EditText pass = passwordEdit("Password (leave blank for legacy SCSTEG01)");
        c.addView(pass); spacer(c,10);
        Button scan = button("SCAN / DECRYPT LSB MESSAGE", GOLD, BG);
        scan.setEnabled(canDecodeSelected());
        scan.setOnClickListener(v -> revealMessage(pass.getText().toString().toCharArray()));
        c.addView(scan); spacer(c,12);
        EditText out = edit(revealed, "Decoded message appears here…", true); out.setKeyListener(null); out.setTextIsSelectable(true);
        c.addView(out, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(260))); body.addView(c);
        return page("Reveal Message", "Auto-detect legacy and authenticated encrypted packets in the selected " + carrierName() + ".", body);
    }

    private View binaryPage() {
        LinearLayout body = column(BG);
        if (selectedBytes.length == 0) { LinearLayout c=card(); c.addView(text("Open an image or WAV file to view its binary structure.",14,MUTED,false)); body.addView(c); return page("Binary Lab", "Read-only hexadecimal and ASCII view of the complete media file.", body); }
        LinearLayout controls = row(BG); Button prev=button("◀ 256",CARD,WHITE), next=button("256 ▶",CARD,WHITE); TextView off=text(String.format(Locale.US,"OFFSET 0x%X",binaryOffset),11,GOLD,true);
        prev.setOnClickListener(v->{binaryOffset=Math.max(0,binaryOffset-256); showPage(Page.BINARY);}); next.setOnClickListener(v->{binaryOffset=Math.min(Math.max(0,selectedBytes.length-1),binaryOffset+256); binaryOffset-=binaryOffset%16; showPage(Page.BINARY);});
        controls.addView(prev); controls.addView(off,new LinearLayout.LayoutParams(0,ViewGroup.LayoutParams.WRAP_CONTENT,1f)); controls.addView(next); body.addView(controls); spacer(body,10);
        LinearLayout c=card(); TextView dump=text(Forensics.hexdump(selectedBytes,binaryOffset,32),10,WHITE,false); dump.setTypeface(Typeface.MONOSPACE); dump.setTextIsSelectable(true); c.addView(dump); body.addView(c);
        return page("Binary Lab", "Read-only hexadecimal and ASCII view of the complete media file.", body);
    }

    private View aboutPage() {
        LinearLayout body=column(BG), c=card(); c.addView(text("WHAT IT DOES",12,GREEN,true));
        c.addView(text("• Hides and reveals messages in lossless PNG images\n• Hides and reveals messages in uncompressed PCM WAV audio\n• Encrypts new messages with AES-256-GCM before LSB embedding\n• Authenticates encrypted data so tampering or a wrong password is rejected\n• Detects suspicious appended bytes and embedded file signatures\n• Audits PNG and RIFF/WAV container structure\n• Calculates SHA-256 and entropy\n• Provides a read-only binary / hex lab",12,WHITE,false)); spacer(c,16);
        c.addView(text("AUDIO MODE",12,GREEN,true));
        c.addView(text("WAV mode supports integer PCM audio at 8, 16, 24, or 32 bits per sample. One hidden bit is stored in each sample's least-significant byte. MP3, AAC, and compressed WAV are intentionally not modified because lossy transcoding can destroy hidden bits.",12,MUTED,false)); spacer(c,16);
        c.addView(text("ENCRYPTION",12,GREEN,true));
        c.addView(text("SCSTEG02 derives a 256-bit key with PBKDF2-HMAC-SHA256 using a fresh random salt, then encrypts with AES-GCM using a fresh random nonce. The password is never written into the image or audio file.",12,MUTED,false)); spacer(c,16);
        c.addView(text("SAFE HANDLING",12,GOLD,true)); c.addView(text("The app never executes discovered content. Treat extracted bytes as untrusted, scan them with your security software, and inspect only files you own or are authorised to examine. A clean result is not a guarantee of safety.",12,MUTED,false)); spacer(c,16);
        c.addView(text("PRIVACY",12,GREEN,true)); c.addView(text("No INTERNET permission is requested. Image/audio processing and encryption stay on-device.",12,MUTED,false)); spacer(c,16);
        c.addView(text("Scarface Stego Studio Mobile v0.3.0  •  SCSTEG01 / SCSTEG02",10,GOLD,true)); body.addView(c);
        return page("Safety & About", "A private mobile workstation for image/audio research, authenticated encryption, and legitimate message privacy.", body);
    }

    private void openMedia() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"image/*", "audio/wav", "audio/x-wav", "audio/wave", "audio/vnd.wave"});
        startActivityForResult(i, REQ_OPEN);
    }

    private void saveStego() {
        if (!canEncodeSelected()) { toast("Open a supported carrier first."); return; }
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT); i.addCategory(Intent.CATEGORY_OPENABLE);
        if (carrierKind == CarrierKind.WAV) {
            i.setType("audio/wav");
            i.putExtra(Intent.EXTRA_TITLE, pendingEncrypt ? "encrypted-message.wav" : "hidden-message-legacy.wav");
        } else {
            i.setType("image/png");
            i.putExtra(Intent.EXTRA_TITLE, pendingEncrypt ? "encrypted-message.png" : "hidden-message-legacy.png");
        }
        startActivityForResult(i, REQ_SAVE_STEGO);
    }

    private void beginExport(int start, int end) {
        exportStart=start; exportEnd=end; Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT); i.addCategory(Intent.CATEGORY_OPENABLE); i.setType("application/octet-stream"); i.putExtra(Intent.EXTRA_TITLE,"suspicious-appended-payload.bin"); startActivityForResult(i,REQ_EXPORT);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode,resultCode,data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            if (requestCode == REQ_SAVE_STEGO) clearPendingPassword();
            return;
        }
        Uri uri=data.getData();
        if (requestCode==REQ_OPEN) scanMedia(uri);
        else if (requestCode==REQ_SAVE_STEGO) encodeTo(uri);
        else if (requestCode==REQ_EXPORT) exportTo(uri);
    }

    private void scanMedia(Uri uri) {
        setStatus("Scanning media…");
        worker.submit(() -> {
            try {
                long t=System.nanoTime();
                byte[] bytes=readAll(uri);
                Forensics.Report r=Forensics.scan(bytes);
                CarrierKind kind;
                WavStegoCodec.Info info = null;

                if (WavStegoCodec.looksLikeWav(bytes)) {
                    kind = CarrierKind.WAV;
                    info = WavStegoCodec.parse(bytes);
                    r.format = info.supportedPcm ? "WAV PCM" : "WAV";
                } else {
                    BitmapFactory.Options o=new BitmapFactory.Options();
                    o.inJustDecodeBounds=true;
                    BitmapFactory.decodeByteArray(bytes,0,bytes.length,o);
                    if (o.outWidth <= 0 || o.outHeight <= 0) throw new Exception("Unsupported carrier. Open a decodable image or RIFF/WAVE file.");
                    kind = CarrierKind.IMAGE;
                    r.width=o.outWidth; r.height=o.outHeight;
                }

                long ms=(System.nanoTime()-t)/1_000_000L;
                String name=queryName(uri);
                CarrierKind finalKind = kind;
                WavStegoCodec.Info finalInfo = info;
                runOnUiThread(()->{
                    selectedUri=uri; selectedBytes=bytes; report=r; wavInfo=finalInfo; carrierKind=finalKind;
                    scanMs=ms; selectedName=name; binaryOffset=0; revealed="";
                    fileLabel.setText(name);
                    if (finalKind == CarrierKind.WAV && finalInfo != null && !finalInfo.supportedPcm)
                        setStatus("WAV inspection complete • audio stego requires uncompressed PCM.");
                    else
                        setStatus((finalKind == CarrierKind.WAV ? "Audio" : "Image") + " forensic scan complete.");
                    showPage(page);
                });
            } catch(Exception e){ runOnUiThread(()->setStatus(e.getMessage())); }
        });
    }

    private void encodeTo(Uri outputUri) {
        final String msg=message;
        final Uri inputUri=selectedUri;
        final CarrierKind kind=carrierKind;
        final byte[] inputBytes=Arrays.copyOf(selectedBytes, selectedBytes.length);
        final boolean encrypted=pendingEncrypt;
        final char[] pass=Arrays.copyOf(pendingHidePassword,pendingHidePassword.length);
        clearPendingPassword();
        setStatus(encrypted ? "Encrypting and encoding message…" : "Encoding legacy message…");

        worker.submit(()->{
            try(OutputStream out=getContentResolver().openOutputStream(outputUri,"w")){
                if (out == null) throw new Exception("Could not open output file.");
                int n;
                if (kind == CarrierKind.WAV) {
                    WavStegoCodec.Result result=WavStegoCodec.encode(inputBytes,msg,pass,encrypted);
                    out.write(result.wav); out.flush(); n=result.packetBytes;
                } else {
                    try(InputStream in=getContentResolver().openInputStream(inputUri)) {
                        Bitmap bmp=StegoCodec.decodeBitmap(in);
                        n=StegoCodec.encode(bmp,msg,pass,encrypted,out);
                        bmp.recycle();
                    }
                }
                int packetBytes=n;
                runOnUiThread(()->{
                    setStatus((encrypted ? "Encrypted SCSTEG02" : "Legacy SCSTEG01") + " message saved in " + (kind == CarrierKind.WAV ? "WAV" : "PNG") + " ("+packetBytes+" packet bytes). Opening output…");
                    scanMedia(outputUri);
                });
            }catch(Exception e){
                runOnUiThread(()->setStatus(e.getMessage()));
            }finally{
                Arrays.fill(pass,'\0');
                Arrays.fill(inputBytes,(byte)0);
            }
        });
    }

    private void revealMessage(char[] password) {
        final Uri uri=selectedUri;
        final CarrierKind kind=carrierKind;
        final byte[] inputBytes=Arrays.copyOf(selectedBytes, selectedBytes.length);
        final char[] pass=Arrays.copyOf(password,password.length);
        Arrays.fill(password,'\0');
        setStatus("Scanning " + carrierName() + " LSB packet…");

        worker.submit(()->{
            try{
                StegoPacket.Decoded d;
                if (kind == CarrierKind.WAV) {
                    d=WavStegoCodec.decode(inputBytes,pass);
                } else {
                    try(InputStream in=getContentResolver().openInputStream(uri)) {
                        Bitmap bmp=StegoCodec.decodeBitmap(in);
                        d=StegoCodec.decode(bmp,pass);
                        bmp.recycle();
                    }
                }
                StegoPacket.Decoded decoded=d;
                runOnUiThread(()->{
                    revealed=decoded.text;
                    if(decoded.encrypted){
                        setStatus("Decrypted "+decoded.payloadBytes+" bytes • AES-256-GCM authenticated • "+decoded.format+" • "+carrierName());
                    }else{
                        setStatus("Revealed "+decoded.payloadBytes+" bytes • CRC "+(decoded.integrityValid?"valid":"FAILED")+" • "+decoded.format+" • "+carrierName());
                    }
                    showPage(Page.REVEAL);
                });
            }catch(Exception e){
                runOnUiThread(()->{revealed="";setStatus(e.getMessage());showPage(Page.REVEAL);});
            }finally{
                Arrays.fill(pass,'\0');
                Arrays.fill(inputBytes,(byte)0);
            }
        });
    }

    private void exportTo(Uri uri) {
        int s=exportStart,e=exportEnd; if(s<0||e<s||e>selectedBytes.length)return;
        try(OutputStream out=getContentResolver().openOutputStream(uri,"w")){out.write(selectedBytes,s,e-s);out.flush();setStatus("Exported "+(e-s)+" untrusted bytes for analysis.");}
        catch(Exception ex){setStatus(ex.getMessage());}
    }

    private byte[] readAll(Uri uri) throws Exception { try(InputStream in=getContentResolver().openInputStream(uri); ByteArrayOutputStream b=new ByteArrayOutputStream()){ if(in==null)throw new Exception("Could not open media file."); byte[] buf=new byte[65536]; int n; while((n=in.read(buf))!=-1)b.write(buf,0,n); return b.toByteArray(); } }
    private String queryName(Uri uri){ try(Cursor c=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){if(c!=null&&c.moveToFirst())return c.getString(0);}catch(Exception ignored){} return "Selected media"; }

    private int rawCarrierCapacity(){
        if (carrierKind == CarrierKind.WAV) return wavInfo == null ? 0 : wavInfo.capacityBytes;
        if (carrierKind == CarrierKind.IMAGE && report != null && report.width > 0 && report.height > 0) {
            long cap=(long)report.width*report.height*3L/8L;
            return (int)Math.max(0,Math.min(Integer.MAX_VALUE,cap));
        }
        return 0;
    }
    private int messageCapacity(boolean encrypted){int overhead=encrypted?StegoPacket.ENCRYPTED_HEADER_BYTES+StegoPacket.GCM_TAG_BYTES:StegoPacket.LEGACY_HEADER_BYTES;return Math.max(0,rawCarrierCapacity()-overhead);}
    private boolean canEncodeSelected(){ return carrierKind == CarrierKind.IMAGE || (carrierKind == CarrierKind.WAV && wavInfo != null && wavInfo.supportedPcm); }
    private boolean canDecodeSelected(){ return canEncodeSelected(); }
    private String carrierName(){ if(carrierKind==CarrierKind.WAV)return "PCM WAV"; if(carrierKind==CarrierKind.IMAGE)return "image"; return "carrier"; }
    private String audioSummary(){
        if (wavInfo == null) return "Unknown audio";
        String ch = wavInfo.channels == 1 ? "mono" : (wavInfo.channels == 2 ? "stereo" : wavInfo.channels + " ch");
        return String.format(Locale.US,"%.1f kHz • %s • %d-bit • %s",wavInfo.sampleRate/1000.0,ch,wavInfo.bitsPerSample,formatDuration(wavInfo.durationSeconds));
    }
    private String formatDuration(double sec){ int total=(int)Math.max(0,Math.round(sec)); return String.format(Locale.US,"%d:%02d",total/60,total%60); }
    private String humanBytes(long bytes){ if(bytes<1024)return bytes+" B"; if(bytes<1024L*1024L)return String.format(Locale.US,"%.1f KB",bytes/1024.0); return String.format(Locale.US,"%.2f MB",bytes/1048576.0); }
    private String dims(){return report!=null&&report.width>0&&report.height>0?report.width+" × "+report.height:"Unknown dimensions";}
    private void clearPendingPassword(){if(pendingHidePassword!=null)Arrays.fill(pendingHidePassword,'\0');pendingHidePassword=new char[0];}
    private Forensics.Severity maxSeverity(Forensics.Report r){Forensics.Severity m=Forensics.Severity.INFO;for(Forensics.Finding f:r.findings)if(f.severity.ordinal()>m.ordinal())m=f.severity;return m;}
    private String severityName(Forensics.Severity s){switch(s){case CRITICAL:return"CRITICAL";case WARNING:return"WARNING";case NOTICE:return"NOTICE";default:return"CLEAR";}}
    private int severityColor(Forensics.Severity s){switch(s){case CRITICAL:return CRITICAL;case WARNING:return GOLD;case NOTICE:return BLUE;default:return GREEN;}}
    private void setStatus(String s){if(s==null||s.isEmpty())s="Ready.";statusLabel.setText(s);}
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_SHORT).show();}

    private LinearLayout column(int color){LinearLayout l=new LinearLayout(this);l.setOrientation(LinearLayout.VERTICAL);l.setBackgroundColor(color);return l;}
    private LinearLayout row(int color){LinearLayout l=new LinearLayout(this);l.setOrientation(LinearLayout.HORIZONTAL);l.setBackgroundColor(color);return l;}
    private TextView text(String s,int sp,int color,boolean bold){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(color);t.setLineSpacing(0,1.15f);if(bold)t.setTypeface(Typeface.DEFAULT,Typeface.BOLD);return t;}
    private Button button(String s,int bg,int fg){Button b=new Button(this);b.setText(s);b.setTextSize(11);b.setTextColor(fg);b.setAllCaps(false);b.setTypeface(Typeface.DEFAULT,Typeface.BOLD);b.setPadding(dp(14),0,dp(14),0);b.setBackground(roundRect(bg==Color.TRANSPARENT?PANEL:bg,8,bg==Color.TRANSPARENT?Color.rgb(41,51,62):bg));return b;}
    private EditText edit(String s,String hint,boolean multi){EditText e=new EditText(this);e.setText(s);e.setHint(hint);e.setHintTextColor(MUTED);e.setTextColor(WHITE);e.setTextSize(13);e.setGravity(Gravity.TOP|Gravity.START);e.setPadding(dp(12),dp(12),dp(12),dp(12));e.setBackground(roundRect(Color.rgb(10,14,19),8,Color.rgb(41,51,62)));e.setSingleLine(!multi);return e;}
    private EditText passwordEdit(String hint){EditText e=edit("",hint,false);e.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);e.setGravity(Gravity.CENTER_VERTICAL|Gravity.START);return e;}
    private LinearLayout card(){LinearLayout c=column(CARD);c.setPadding(dp(15),dp(15),dp(15),dp(15));c.setBackground(roundRect(CARD,10,Color.rgb(41,51,62)));return c;}
    private View metricCard(String label,String value,int color){LinearLayout c=card();c.addView(text(label,10,MUTED,true));spacer(c,7);c.addView(text(value,24,color,true));return c;}
    private GradientDrawable roundRect(int fill,int radius,int stroke){GradientDrawable g=new GradientDrawable();g.setColor(fill);g.setCornerRadius(dp(radius));g.setStroke(dp(1),stroke);return g;}
    private void spacer(LinearLayout l,int dp){View v=new View(this);l.addView(v,new LinearLayout.LayoutParams(1,dp(dp)));}
    private int dp(int v){return Math.round(v*getResources().getDisplayMetrics().density);}
}
