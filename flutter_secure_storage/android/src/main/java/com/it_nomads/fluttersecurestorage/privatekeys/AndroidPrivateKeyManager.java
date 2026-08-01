package com.it_nomads.fluttersecurestorage.privatekeys;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;

/**
 * Android Keystore / software private-key manager for the unified private-key API.
 * Channel: plugins.it_nomads.com/flutter_secure_storage/desktop_keys
 */
public final class AndroidPrivateKeyManager implements MethodChannel.MethodCallHandler {

    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String META_PREFS = "fss_dsk_meta";
    private static final String WRAP_PREFS = "fss_dsk_wrap";
    private static final String ALIAS_PREFIX = ".fss.dsk.";
    private static final String WRAP_ALIAS_PREFIX = ".fss.dsk.wrap.";
    private static final byte[] FSS_EPK1 = "FSS-EPK1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] FSS_CSR1 = "FSS-CSR1".getBytes(StandardCharsets.UTF_8);
    private static final int GCM_TAG_BITS = 128;
    private static final int PBKDF2_ITERS = 100000;

    private final Context context;
    private final SecureRandom secureRandom = new SecureRandom();

    public AndroidPrivateKeyManager(Context context) {
        this.context = context.getApplicationContext();
    }

    @Override
    public void onMethodCall(@NonNull MethodCall call, @NonNull MethodChannel.Result result) {
        try {
            switch (call.method) {
                case "getCapabilities":
                    result.success(getCapabilities(argString(call, "protection", "platformDefault")));
                    break;
                case "createPrivateKey":
                    result.success(createPrivateKey(call.arguments()));
                    break;
                case "getPrivateKeyHandle":
                    result.success(getPrivateKeyHandle(argString(call, "keyId", "")));
                    break;
                case "listPrivateKeys":
                    result.success(listPrivateKeys());
                    break;
                case "deletePrivateKey":
                    deletePrivateKey(argString(call, "keyId", ""));
                    result.success(null);
                    break;
                case "exportPrivateKey":
                    result.success(exportPrivateKey(call.arguments()));
                    break;
                case "importPrivateKey":
                    result.success(importPrivateKey(call.arguments()));
                    break;
                case "sign":
                    result.success(sign(call.arguments()));
                    break;
                case "getPublicKey":
                    result.success(getPublicKey(argString(call, "keyId", "")));
                    break;
                case "createCertificateSigningRequest":
                    result.success(createCsr(call.arguments()));
                    break;
                default:
                    result.notImplemented();
                    break;
            }
        } catch (PrivateKeyException e) {
            Map<String, Object> details = new HashMap<>();
            details.put("provider", "android");
            result.error(e.code, e.getMessage(), details);
        } catch (Exception e) {
            Map<String, Object> details = new HashMap<>();
            details.put("provider", "android");
            result.error("providerUnavailable", e.getMessage(), details);
        }
    }

    private Map<String, Object> getCapabilities(String protection) {
        boolean strongBox = hasStrongBox();
        boolean tee = true; // Keystore present on API 23+
        String selected = "android_keystore";
        String fallback = null;
        boolean hw = tee;
        boolean privateHw = tee;

        switch (protection) {
            case "hardwareBackedRequired":
                if (!tee) {
                    selected = "none";
                    hw = false;
                    privateHw = false;
                } else if (strongBox) {
                    selected = "strongbox";
                }
                break;
            case "hardwareBackedPreferred":
                if (strongBox) {
                    selected = "strongbox";
                } else if (!tee) {
                    selected = "software";
                    fallback = "Android Keystore unavailable";
                    hw = false;
                    privateHw = false;
                }
                break;
            case "softwareProtected":
                selected = "software";
                hw = false;
                privateHw = false;
                break;
            default:
                break;
        }

        List<String> providers = new ArrayList<>();
        providers.add("android_keystore");
        providers.add("software");
        if (strongBox) {
            providers.add("strongbox");
        }

        List<String> algorithms = new ArrayList<>();
        algorithms.add("ecP256");
        algorithms.add("rsa2048");
        algorithms.add("rsa3072");

        List<String> formats = new ArrayList<>();
        formats.add("pemPkcs8");
        formats.add("derPkcs8");

        Map<String, Object> map = new HashMap<>();
        map.put("platform", "android");
        map.put("availableProviders", providers);
        map.put("selectedProvider", selected);
        map.put("hardwareAvailable", tee || strongBox);
        map.put("storageProtectionHardwareBacked", hw);
        map.put("privateKeyHardwareBacked", privateHw && !"software".equals(selected));
        map.put("supportsNonExportableKeys", true);
        map.put("supportsExportableKeys", true);
        map.put("supportsUserPresence", Build.VERSION.SDK_INT >= Build.VERSION_CODES.M);
        map.put("supportsMachineScope", false);
        map.put("supportsCsrGeneration", true);
        map.put("supportedAlgorithms", algorithms);
        map.put("supportedExportFormats", formats);
        map.put("fallbackReason", fallback);
        map.put("sameUserCompromiseResistant", privateHw && !"software".equals(selected));
        map.put("rootCompromiseResistant", strongBox && "strongbox".equals(selected));
        return map;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> createPrivateKey(Object rawArgs) throws Exception {
        Map<String, Object> args = rawArgs instanceof Map ? (Map<String, Object>) rawArgs : new HashMap<>();
        String keyId = stringArg(args, "keyId", "");
        validateKeyId(keyId);
        if (loadHandle(keyId) != null) {
            throw new PrivateKeyException("keyAlreadyExists", "private key already exists");
        }

        String algorithm = stringArg(args, "algorithm", "ecP256");
        String protection = stringArg(args, "protection", "platformDefault");
        String exportPolicy = stringArg(args, "exportPolicy", "nonExportable");
        boolean requireUserPresence = boolArg(args, "requireUserPresence", false);
        boolean machineScoped = boolArg(args, "machineScoped", false);
        if (machineScoped) {
            throw new PrivateKeyException("invalidConfiguration", "machineScoped is not supported on Android");
        }
        if ("ed25519".equals(algorithm)) {
            throw new PrivateKeyException("algorithmUnsupported", "ed25519 is not supported on Android Keystore");
        }

        boolean exportable = "exportableEncrypted".equals(exportPolicy);
        boolean wantHw = "hardwareBackedRequired".equals(protection)
                || "hardwareBackedPreferred".equals(protection)
                || "platformDefault".equals(protection);

        if (!exportable && wantHw && !"softwareProtected".equals(protection)) {
            try {
                return createHardwareKey(keyId, algorithm, protection, requireUserPresence);
            } catch (PrivateKeyException e) {
                if ("hardwareBackedRequired".equals(protection)) {
                    throw e;
                }
                // fall through to software for preferred/default
            }
        }
        if (!exportable && "hardwareBackedRequired".equals(protection)) {
            throw new PrivateKeyException("hardwareRequiredButUnavailable", "Android Keystore hardware key unavailable");
        }
        return createSoftwareExportableKey(keyId, algorithm, exportable, requireUserPresence, protection);
    }

    private Map<String, Object> createHardwareKey(
            String keyId,
            String algorithm,
            String protection,
            boolean requireUserPresence
    ) throws Exception {
        String alias = aliasFor(keyId);
        KeyPairGenerator kpg;
        KeyGenParameterSpec.Builder builder;

        if ("ecP256".equals(algorithm)) {
            kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE);
            builder = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256);
        } else if ("rsa2048".equals(algorithm) || "rsa3072".equals(algorithm)) {
            int bits = "rsa3072".equals(algorithm) ? 3072 : 2048;
            kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE);
            builder = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
                    .setKeySize(bits)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);
        } else {
            throw new PrivateKeyException("algorithmUnsupported", "unsupported algorithm " + algorithm);
        }

        builder.setUserAuthenticationRequired(requireUserPresence);
        if (requireUserPresence && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
        }

        boolean strongBox = hasStrongBox();
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                builder.setIsStrongBoxBacked(true);
            } catch (Exception ignored) {
                strongBox = false;
            }
        }
        if ("hardwareBackedRequired".equals(protection) && !isKeystoreUsable()) {
            throw new PrivateKeyException("hardwareRequiredButUnavailable", "Android Keystore unavailable");
        }

        kpg.initialize(builder.build());
        KeyPair pair = kpg.generateKeyPair();

        boolean hwBacked = isPrivateKeyHardwareBacked(pair.getPrivate());
        if ("hardwareBackedRequired".equals(protection) && !hwBacked) {
            deleteAlias(alias);
            throw new PrivateKeyException("hardwareRequiredButUnavailable", "key was not hardware-backed");
        }

        String provider = strongBox && hwBacked ? "strongbox" : "android_keystore";
        Map<String, Object> handle = handleMap(
                keyId,
                provider,
                algorithm,
                "nonExportable",
                hwBacked,
                hwBacked,
                true,
                false,
                requireUserPresence
        );
        storeHandle(keyId, handle);
        storePublic(keyId, pair.getPublic().getEncoded());
        return handle;
    }

    private Map<String, Object> createSoftwareExportableKey(
            String keyId,
            String algorithm,
            boolean exportable,
            boolean requireUserPresence,
            String protection
    ) throws Exception {
        KeyPair pair = generateSoftwarePair(algorithm);
        byte[] privatePkcs8 = pair.getPrivate().getEncoded();
        try {
            byte[] wrapKey = ensureWrapKey(keyId);
            byte[] sealed = aesGcmEncrypt(wrapKey, privatePkcs8);
            prefs(WRAP_PREFS).edit().putString(keyId, Base64.encodeToString(sealed, Base64.NO_WRAP)).apply();
            storePublic(keyId, pair.getPublic().getEncoded());

            boolean storageHw = isWrapKeyHardwareBacked(keyId);
            Map<String, Object> handle = handleMap(
                    keyId,
                    "software",
                    algorithm,
                    exportable ? "exportableEncrypted" : "nonExportable",
                    false,
                    storageHw,
                    true,
                    false,
                    requireUserPresence
            );
            storeHandle(keyId, handle);
            return handle;
        } finally {
            zero(privatePkcs8);
        }
    }

    private KeyPair generateSoftwarePair(String algorithm) throws Exception {
        if ("ecP256".equals(algorithm)) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"), secureRandom);
            return kpg.generateKeyPair();
        }
        if ("rsa2048".equals(algorithm) || "rsa3072".equals(algorithm)) {
            int bits = "rsa3072".equals(algorithm) ? 3072 : 2048;
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(bits, secureRandom);
            return kpg.generateKeyPair();
        }
        throw new PrivateKeyException("algorithmUnsupported", "unsupported algorithm " + algorithm);
    }

    @Nullable
    private Map<String, Object> getPrivateKeyHandle(String keyId) throws Exception {
        return loadHandle(keyId);
    }

    private List<Map<String, Object>> listPrivateKeys() throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        SharedPreferences prefs = prefs(META_PREFS);
        for (String key : prefs.getAll().keySet()) {
            Map<String, Object> handle = loadHandle(key);
            if (handle != null) {
                out.add(handle);
            }
        }
        return out;
    }

    private void deletePrivateKey(String keyId) throws Exception {
        Map<String, Object> handle = loadHandle(keyId);
        if (handle == null) {
            throw new PrivateKeyException("keyNotFound", "private key not found");
        }
        deleteAlias(aliasFor(keyId));
        deleteAlias(wrapAliasFor(keyId));
        prefs(META_PREFS).edit().remove(keyId).apply();
        prefs(WRAP_PREFS).edit().remove(keyId).remove(keyId + ".pub").apply();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> exportPrivateKey(Object rawArgs) throws Exception {
        Map<String, Object> args = rawArgs instanceof Map ? (Map<String, Object>) rawArgs : new HashMap<>();
        String keyId = stringArg(args, "keyId", "");
        String passphrase = passphraseFrom(args);
        String encoding = stringArg(args, "encoding", "pemPkcs8");
        if (passphrase.isEmpty()) {
            throw new PrivateKeyException("invalidExportPassphrase", "export passphrase must be non-empty");
        }
        Map<String, Object> handle = loadHandle(keyId);
        if (handle == null) {
            throw new PrivateKeyException("keyNotFound", "private key not found");
        }
        if (!"exportableEncrypted".equals(handle.get("exportPolicy"))) {
            throw new PrivateKeyException("keyNotExportable", "private key was created as non-exportable");
        }
        byte[] privatePkcs8 = unwrapSoftwarePrivate(keyId);
        try {
            byte[] encrypted = encryptFssEpk1(privatePkcs8, passphrase);
            Map<String, Object> out = new HashMap<>();
            if ("derPkcs8".equals(encoding)) {
                out.put("bytes", encrypted);
                out.put("encoding", "derPkcs8");
            } else {
                out.put("bytes", toPem(encrypted).getBytes(StandardCharsets.UTF_8));
                out.put("encoding", "pemPkcs8");
            }
            out.put("kdf", "pbkdf2Sha256");
            return out;
        } finally {
            zero(privatePkcs8);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> importPrivateKey(Object rawArgs) throws Exception {
        Map<String, Object> args = rawArgs instanceof Map ? (Map<String, Object>) rawArgs : new HashMap<>();
        String keyId = stringArg(args, "keyId", "");
        validateKeyId(keyId);
        if (loadHandle(keyId) != null) {
            throw new PrivateKeyException("keyAlreadyExists", "private key already exists");
        }
        if (boolArg(args, "machineScoped", false)) {
            throw new PrivateKeyException("invalidConfiguration", "machineScoped is not supported on Android");
        }
        String passphrase = passphraseFrom(args);
        byte[] encrypted = bytesArg(args, "encryptedKey");
        if (encrypted == null) {
            encrypted = bytesArg(args, "bytes");
        }
        if (encrypted == null) {
            throw new PrivateKeyException("corruptRecord", "encrypted key bytes required");
        }
        // Strip PEM if present
        String asText = new String(encrypted, StandardCharsets.UTF_8);
        if (asText.contains("BEGIN ENCRYPTED PRIVATE KEY")) {
            encrypted = fromPem(asText);
        }
        byte[] privatePkcs8 = decryptFssEpk1(encrypted, passphrase);
        try {
            String algorithm = "ecP256";
            PrivateKey privateKey;
            PublicKey publicKey;
            try {
                privateKey = KeyFactory.getInstance("EC").generatePrivate(
                        new java.security.spec.PKCS8EncodedKeySpec(privatePkcs8));
                publicKey = EcP256.publicFromPrivate((java.security.interfaces.ECPrivateKey) privateKey);
            } catch (Exception ecFail) {
                privateKey = KeyFactory.getInstance("RSA").generatePrivate(
                        new java.security.spec.PKCS8EncodedKeySpec(privatePkcs8));
                algorithm = privatePkcs8.length > 1200 ? "rsa3072" : "rsa2048";
                publicKey = deriveRsaPublic(privateKey);
            }
            byte[] wrapKey = ensureWrapKey(keyId);
            byte[] sealed = aesGcmEncrypt(wrapKey, privatePkcs8);
            prefs(WRAP_PREFS).edit().putString(keyId, Base64.encodeToString(sealed, Base64.NO_WRAP)).apply();
            storePublic(keyId, publicKey.getEncoded());
            String exportPolicy = stringArg(args, "exportPolicy", "exportableEncrypted");
            boolean requireUserPresence = boolArg(args, "requireUserPresence", false);
            Map<String, Object> handle = handleMap(
                    keyId,
                    "software",
                    algorithm,
                    exportPolicy,
                    false,
                    isWrapKeyHardwareBacked(keyId),
                    true,
                    false,
                    requireUserPresence
            );
            storeHandle(keyId, handle);
            Map<String, Object> result = new HashMap<>();
            result.put("handle", handle);
            return result;
        } finally {
            zero(privatePkcs8);
        }
    }

    @SuppressWarnings("unchecked")
    private byte[] sign(Object rawArgs) throws Exception {
        Map<String, Object> args = rawArgs instanceof Map ? (Map<String, Object>) rawArgs : new HashMap<>();
        String keyId = stringArg(args, "keyId", "");
        byte[] data = bytesArg(args, "data");
        if (data == null) {
            throw new PrivateKeyException("invalidConfiguration", "data required");
        }
        Map<String, Object> handle = loadHandle(keyId);
        if (handle == null) {
            throw new PrivateKeyException("keyNotFound", "private key not found");
        }
        String algorithm = String.valueOf(handle.get("algorithm"));
        boolean hardware = Boolean.TRUE.equals(handle.get("hardwareBacked"));

        PrivateKey privateKey;
        if (hardware) {
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            privateKey = (PrivateKey) ks.getKey(aliasFor(keyId), null);
            if (privateKey == null) {
                throw new PrivateKeyException("keyNotFound", "keystore key missing");
            }
        } else {
            byte[] pkcs8 = unwrapSoftwarePrivate(keyId);
            try {
                String kf = algorithm.startsWith("rsa") ? "RSA" : "EC";
                privateKey = KeyFactory.getInstance(kf)
                        .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
            } finally {
                zero(pkcs8);
            }
        }

        String sigAlg = algorithm.startsWith("rsa") ? "SHA256withRSA" : "SHA256withECDSA";
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private byte[] getPublicKey(String keyId) throws Exception {
        Map<String, Object> handle = loadHandle(keyId);
        if (handle == null) {
            throw new PrivateKeyException("keyNotFound", "private key not found");
        }
        if (Boolean.TRUE.equals(handle.get("hardwareBacked"))) {
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            PublicKey publicKey = ks.getCertificate(aliasFor(keyId)).getPublicKey();
            return publicKey.getEncoded();
        }
        String b64 = prefs(WRAP_PREFS).getString(keyId + ".pub", null);
        if (b64 == null) {
            throw new PrivateKeyException("keyNotFound", "public key unavailable");
        }
        return Base64.decode(b64, Base64.NO_WRAP);
    }

    @SuppressWarnings("unchecked")
    private byte[] createCsr(Object rawArgs) throws Exception {
        Map<String, Object> args = rawArgs instanceof Map ? (Map<String, Object>) rawArgs : new HashMap<>();
        String keyId = stringArg(args, "keyId", "");
        String subject = stringArg(args, "subjectDistinguishedName", "");
        byte[] subjectBytes = subject.getBytes(StandardCharsets.UTF_8);
        Map<String, Object> signArgs = new HashMap<>();
        signArgs.put("keyId", keyId);
        signArgs.put("data", subjectBytes);
        byte[] signature = sign(signArgs);

        ByteBuffer buf = ByteBuffer.allocate(FSS_CSR1.length + 4 + subjectBytes.length + 4 + signature.length);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.put(FSS_CSR1);
        buf.putInt(subjectBytes.length);
        buf.put(subjectBytes);
        buf.putInt(signature.length);
        buf.put(signature);
        return buf.array();
    }

    // --- helpers ---

    private byte[] ensureWrapKey(String keyId) throws Exception {
        String alias = wrapAliasFor(keyId);
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        if (!ks.containsAlias(alias)) {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
            )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256);
            if (hasStrongBox() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    builder.setIsStrongBoxBacked(true);
                } catch (Exception ignored) {
                }
            }
            kg.init(builder.build());
            kg.generateKey();
        }
        // Return a random DEK encrypted by the wrap key — store DEK alongside
        String dekB64 = prefs(WRAP_PREFS).getString(keyId + ".dek", null);
        if (dekB64 != null) {
            byte[] sealedDek = Base64.decode(dekB64, Base64.NO_WRAP);
            return aesGcmDecryptWithKeystore(alias, sealedDek);
        }
        byte[] dek = new byte[32];
        secureRandom.nextBytes(dek);
        byte[] sealed = aesGcmEncryptWithKeystore(alias, dek);
        prefs(WRAP_PREFS).edit().putString(keyId + ".dek", Base64.encodeToString(sealed, Base64.NO_WRAP)).apply();
        return dek;
    }

    private byte[] unwrapSoftwarePrivate(String keyId) throws Exception {
        String b64 = prefs(WRAP_PREFS).getString(keyId, null);
        if (b64 == null) {
            throw new PrivateKeyException("keyUnwrapFailed", "unable to unwrap private key");
        }
        byte[] sealed = Base64.decode(b64, Base64.NO_WRAP);
        byte[] wrapKey = ensureWrapKey(keyId);
        try {
            return aesGcmDecrypt(wrapKey, sealed);
        } finally {
            zero(wrapKey);
        }
    }

    private byte[] aesGcmEncryptWithKeystore(String alias, byte[] plaintext) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        SecretKey key = (SecretKey) ks.getKey(alias, null);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] ct = cipher.doFinal(plaintext);
        ByteBuffer buf = ByteBuffer.allocate(1 + iv.length + ct.length);
        buf.put((byte) iv.length);
        buf.put(iv);
        buf.put(ct);
        return buf.array();
    }

    private byte[] aesGcmDecryptWithKeystore(String alias, byte[] sealed) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(sealed);
        int ivLen = buf.get() & 0xff;
        byte[] iv = new byte[ivLen];
        buf.get(iv);
        byte[] ct = new byte[buf.remaining()];
        buf.get(ct);
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        SecretKey key = (SecretKey) ks.getKey(alias, null);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(ct);
    }

    private byte[] aesGcmEncrypt(byte[] key, byte[] plaintext) throws Exception {
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = cipher.doFinal(plaintext);
        ByteBuffer buf = ByteBuffer.allocate(iv.length + ct.length);
        buf.put(iv);
        buf.put(ct);
        return buf.array();
    }

    private byte[] aesGcmDecrypt(byte[] key, byte[] sealed) throws Exception {
        byte[] iv = new byte[12];
        System.arraycopy(sealed, 0, iv, 0, 12);
        byte[] ct = new byte[sealed.length - 12];
        System.arraycopy(sealed, 12, ct, 0, ct.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(ct);
    }

    private byte[] encryptFssEpk1(byte[] privatePkcs8, String passphrase) throws Exception {
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        byte[] derived = pbkdf2(passphrase, salt, PBKDF2_ITERS, 32);
        try {
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derived, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] sealed = cipher.doFinal(privatePkcs8);
            // sealed = ciphertext || tag (Android appends tag)
            byte[] tag = new byte[16];
            byte[] ct = new byte[sealed.length - 16];
            System.arraycopy(sealed, 0, ct, 0, ct.length);
            System.arraycopy(sealed, ct.length, tag, 0, 16);

            ByteBuffer buf = ByteBuffer.allocate(
                    FSS_EPK1.length + 4 + 1 + salt.length + 1 + iv.length + 1 + tag.length + 4 + ct.length
            );
            buf.order(ByteOrder.LITTLE_ENDIAN);
            buf.put(FSS_EPK1);
            buf.putInt(PBKDF2_ITERS);
            buf.put((byte) salt.length);
            buf.put(salt);
            buf.put((byte) iv.length);
            buf.put(iv);
            buf.put((byte) 16);
            buf.put(tag);
            buf.putInt(ct.length);
            buf.put(ct);
            return buf.array();
        } finally {
            zero(derived);
        }
    }

    private byte[] decryptFssEpk1(byte[] blob, String passphrase) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        byte[] magic = new byte[FSS_EPK1.length];
        buf.get(magic);
        if (!java.util.Arrays.equals(magic, FSS_EPK1)) {
            throw new PrivateKeyException("corruptRecord", "not FSS-EPK1");
        }
        int iters = buf.getInt();
        int saltLen = buf.get() & 0xff;
        byte[] salt = new byte[saltLen];
        buf.get(salt);
        int ivLen = buf.get() & 0xff;
        byte[] iv = new byte[ivLen];
        buf.get(iv);
        int tagLen = buf.get() & 0xff;
        byte[] tag = new byte[tagLen];
        buf.get(tag);
        int ctLen = buf.getInt();
        byte[] ct = new byte[ctLen];
        buf.get(ct);

        byte[] derived = pbkdf2(passphrase, salt, iters, 32);
        try {
            byte[] sealed = new byte[ct.length + tag.length];
            System.arraycopy(ct, 0, sealed, 0, ct.length);
            System.arraycopy(tag, 0, sealed, ct.length, tag.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derived, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(sealed);
        } finally {
            zero(derived);
        }
    }

    private byte[] pbkdf2(String passphrase, byte[] salt, int iters, int len) throws Exception {
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                passphrase.toCharArray(), salt, iters, len * 8
        );
        javax.crypto.SecretKeyFactory factory =
                javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        try {
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private String toPem(byte[] der) {
        String b64 = Base64.encodeToString(der, Base64.NO_WRAP);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ENCRYPTED PRIVATE KEY-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END ENCRYPTED PRIVATE KEY-----\n");
        return sb.toString();
    }

    private byte[] fromPem(String pem) {
        String body = pem
                .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.decode(body, Base64.DEFAULT);
    }

    private PublicKey deriveRsaPublic(PrivateKey privateKey) throws Exception {
        if (privateKey instanceof java.security.interfaces.RSAPrivateCrtKey) {
            java.security.interfaces.RSAPrivateCrtKey crt =
                    (java.security.interfaces.RSAPrivateCrtKey) privateKey;
            java.security.spec.RSAPublicKeySpec pubSpec =
                    new java.security.spec.RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent());
            return KeyFactory.getInstance("RSA").generatePublic(pubSpec);
        }
        throw new PrivateKeyException("algorithmUnsupported", "cannot derive RSA public key");
    }

    private void storePublic(String keyId, byte[] spki) {
        prefs(WRAP_PREFS).edit()
                .putString(keyId + ".pub", Base64.encodeToString(spki, Base64.NO_WRAP))
                .apply();
    }

    private void storeHandle(String keyId, Map<String, Object> handle) throws Exception {
        JSONObject json = new JSONObject();
        for (Map.Entry<String, Object> e : handle.entrySet()) {
            json.put(e.getKey(), e.getValue());
        }
        prefs(META_PREFS).edit().putString(keyId, json.toString()).apply();
    }

    @Nullable
    private Map<String, Object> loadHandle(String keyId) throws Exception {
        String raw = prefs(META_PREFS).getString(keyId, null);
        if (raw == null) {
            return null;
        }
        JSONObject json = new JSONObject(raw);
        Map<String, Object> map = new HashMap<>();
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            String k = keys.next();
            map.put(k, json.get(k));
        }
        return map;
    }

    private Map<String, Object> handleMap(
            String keyId,
            String provider,
            String algorithm,
            String exportPolicy,
            boolean hardwareBacked,
            boolean storageHw,
            boolean deviceBound,
            boolean machineScoped,
            boolean userPresence
    ) {
        Map<String, Object> map = new HashMap<>();
        map.put("keyId", keyId);
        map.put("provider", provider);
        map.put("algorithm", algorithm);
        map.put("exportPolicy", exportPolicy);
        map.put("hardwareBacked", hardwareBacked);
        map.put("storageProtectionHardwareBacked", storageHw);
        map.put("deviceBound", deviceBound);
        map.put("machineScoped", machineScoped);
        map.put("userPresenceRequired", userPresence);
        return map;
    }

    private void validateKeyId(String keyId) throws PrivateKeyException {
        if (keyId == null || keyId.isEmpty() || keyId.contains("..") || keyId.contains("\\") || keyId.contains("/")) {
            throw new PrivateKeyException("invalidConfiguration", "unsafe or empty keyId");
        }
    }

    private String aliasFor(String keyId) {
        return context.getPackageName() + ALIAS_PREFIX + keyId;
    }

    private String wrapAliasFor(String keyId) {
        return context.getPackageName() + WRAP_ALIAS_PREFIX + keyId;
    }

    private void deleteAlias(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias);
            }
        } catch (Exception ignored) {
        }
    }

    private boolean hasStrongBox() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                && context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    }

    private boolean isKeystoreUsable() {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isPrivateKeyHardwareBacked(PrivateKey key) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), KEYSTORE);
                KeyInfo info = factory.getKeySpec(key, KeyInfo.class);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    return info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                            || info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_STRONGBOX;
                }
                return info.isInsideSecureHardware();
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private boolean isWrapKeyHardwareBacked(String keyId) {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            SecretKey key = (SecretKey) ks.getKey(wrapAliasFor(keyId), null);
            if (key == null) {
                return false;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), KEYSTORE);
                KeyInfo info = factory.getKeySpec(key, KeyInfo.class);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    return info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                            || info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_STRONGBOX;
                }
                return info.isInsideSecureHardware();
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private SharedPreferences prefs(String name) {
        return context.getSharedPreferences(name, Context.MODE_PRIVATE);
    }

    private static String argString(MethodCall call, String key, String def) {
        Object v = call.argument(key);
        return v == null ? def : String.valueOf(v);
    }

    private static String stringArg(Map<String, Object> args, String key, String def) {
        Object v = args.get(key);
        return v == null ? def : String.valueOf(v);
    }

    private static boolean boolArg(Map<String, Object> args, String key, boolean def) {
        Object v = args.get(key);
        if (v instanceof Boolean) {
            return (Boolean) v;
        }
        return def;
    }

    @Nullable
    private static byte[] bytesArg(Map<String, Object> args, String key) {
        Object v = args.get(key);
        if (v instanceof byte[]) {
            return (byte[]) v;
        }
        return null;
    }

    private static String passphraseFrom(Map<String, Object> args) {
        Object bytes = args.get("passphraseBytes");
        if (bytes instanceof byte[]) {
            return new String((byte[]) bytes, StandardCharsets.UTF_8);
        }
        Object s = args.get("passphrase");
        return s == null ? "" : String.valueOf(s);
    }

    private static void zero(byte[] data) {
        if (data != null) {
            java.util.Arrays.fill(data, (byte) 0);
        }
    }

    static final class PrivateKeyException extends Exception {
        final String code;

        PrivateKeyException(String code, String message) {
            super(message);
            this.code = code;
        }
    }
}
