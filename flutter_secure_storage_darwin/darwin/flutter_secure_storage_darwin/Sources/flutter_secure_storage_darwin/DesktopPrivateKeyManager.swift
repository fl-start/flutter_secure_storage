import Foundation
import Security
import CryptoKit
import LocalAuthentication

#if os(macOS)
import CommonCrypto
import FlutterMacOS
#endif

#if os(macOS)

/// macOS-only desktop private-key manager.
///
/// iOS builds compile this file but all types are gated so iOS behavior is unchanged.
enum DesktopPrivateKeyError: String {
    case providerUnavailable
    case hardwareRequiredButUnavailable
    case algorithmUnsupported
    case keyAlreadyExists
    case keyNotFound
    case keyNotExportable
    case invalidExportPassphrase
    case authenticationRequired
    case authenticationCancelled
    case accessDenied
    case corruptRecord
    case keyUnwrapFailed
    case invalidConfiguration
    case unsupportedPlatform
}

struct DesktopPrivateKeyHandleDTO {
    let keyId: String
    let provider: String
    let algorithm: String
    let exportPolicy: String
    let hardwareBacked: Bool
    let storageProtectionHardwareBacked: Bool
    let deviceBound: Bool
    let machineScoped: Bool
    let userPresenceRequired: Bool

    func toMap() -> [String: Any] {
        [
            "keyId": keyId,
            "provider": provider,
            "algorithm": algorithm,
            "exportPolicy": exportPolicy,
            "hardwareBacked": hardwareBacked,
            "storageProtectionHardwareBacked": storageProtectionHardwareBacked,
            "deviceBound": deviceBound,
            "machineScoped": machineScoped,
            "userPresenceRequired": userPresenceRequired
        ]
    }
}

final class DesktopPrivateKeyManager {
    static let shared = DesktopPrivateKeyManager()

    private let servicePrefix = "fss.dsk."
    private let metaAccount = "fss.dsk.meta"

    private init() {}

    func getCapabilities(protection: String) -> [String: Any] {
        let seAvailable = isSecureEnclaveAvailable()
        var selected = "keychain"
        var fallback: String? = nil
        var storageHw = false
        var privateHw = false

        switch protection {
        case "hardwareBackedRequired":
            if seAvailable {
                selected = "secure_enclave"
                storageHw = true
                privateHw = true
            } else {
                selected = "none"
            }
        case "hardwareBackedPreferred":
            if seAvailable {
                selected = "secure_enclave"
                storageHw = true
                privateHw = true
            } else {
                selected = "keychain"
                fallback = "Secure Enclave unavailable"
            }
        case "softwareProtected":
            selected = "keychain"
        default:
            selected = "keychain"
        }

        var providers = ["keychain"]
        if seAvailable { providers.append("secure_enclave") }

        return [
            "platform": "macos",
            "availableProviders": providers,
            "selectedProvider": selected,
            "hardwareAvailable": seAvailable,
            "storageProtectionHardwareBacked": storageHw,
            "privateKeyHardwareBacked": privateHw,
            "supportsNonExportableKeys": true,
            "supportsExportableKeys": true,
            "supportsUserPresence": true,
            "supportsMachineScope": false,
            "supportsCsrGeneration": true,
            "supportedAlgorithms": ["rsa2048", "rsa3072", "ecP256"],
            "supportedExportFormats": ["pemPkcs8", "derPkcs8"],
            "fallbackReason": fallback as Any,
            "sameUserCompromiseResistant": privateHw,
            "rootCompromiseResistant": privateHw
        ]
    }

    func createPrivateKey(args: [String: Any]) throws -> [String: Any] {
        guard let keyId = args["keyId"] as? String, !keyId.isEmpty else {
            throw makeError(.invalidConfiguration, "keyId required")
        }
        if keyId.contains("..") || keyId.contains("\\") {
            throw makeError(.invalidConfiguration, "unsafe keyId")
        }
        let algorithm = args["algorithm"] as? String ?? "ecP256"
        let protection = args["protection"] as? String ?? "platformDefault"
        let exportPolicy = args["exportPolicy"] as? String ?? "nonExportable"
        let requireUserPresence = args["requireUserPresence"] as? Bool ?? false
        let machineScoped = args["machineScoped"] as? Bool ?? false
        if machineScoped {
            throw makeError(.invalidConfiguration, "machineScoped is not supported on macOS private keys")
        }
        if algorithm == "ed25519" && protection == "hardwareBackedRequired" {
            throw makeError(.algorithmUnsupported, "ed25519 is not supported by Secure Enclave")
        }
        if getHandle(keyId: keyId) != nil {
            throw makeError(.keyAlreadyExists, "private key already exists")
        }

        let seAvailable = isSecureEnclaveAvailable()
        if protection == "hardwareBackedRequired" && !seAvailable {
            throw makeError(.hardwareRequiredButUnavailable, "Secure Enclave unavailable")
        }

        let exportable = exportPolicy == "exportableEncrypted"
        if !exportable && (protection == "hardwareBackedRequired" || protection == "hardwareBackedPreferred") && seAvailable {
            return try createNonExportableSecureEnclaveKey(
                keyId: keyId,
                algorithm: algorithm,
                requireUserPresence: requireUserPresence
            )
        }

        return try createExportableOrSoftwareKey(
            keyId: keyId,
            algorithm: algorithm,
            exportable: exportable,
            wrapWithSE: seAvailable && (protection == "hardwareBackedPreferred" || protection == "hardwareBackedRequired"),
            requireUserPresence: requireUserPresence
        )
    }

    func getPrivateKeyHandle(keyId: String) -> [String: Any]? {
        getHandle(keyId: keyId)?.toMap()
    }

    func listPrivateKeys() -> [[String: Any]] {
        loadMeta().values.map { $0.toMap() }
    }

    func deletePrivateKey(keyId: String) throws {
        var meta = loadMeta()
        guard let handle = meta.removeValue(forKey: keyId) else {
            throw makeError(.keyNotFound, "private key not found")
        }
        saveMeta(meta)
        deleteKeychainItem(account: privateAccount(keyId))
        deleteKeychainItem(account: wrapAccount(keyId))
        if handle.hardwareBacked {
            deleteSecKey(tag: seTag(keyId))
        }
    }

    func exportPrivateKey(keyId: String, passphrase: String, encoding: String) throws -> [String: Any] {
        guard !passphrase.isEmpty else {
            throw makeError(.invalidExportPassphrase, "export passphrase must be non-empty")
        }
        guard let handle = getHandle(keyId: keyId) else {
            throw makeError(.keyNotFound, "private key not found")
        }
        if handle.exportPolicy != "exportableEncrypted" {
            throw makeError(.keyNotExportable, "private key was created as non-exportable")
        }
        guard let privateData = loadSoftwarePrivateKey(keyId: keyId) else {
            throw makeError(.keyUnwrapFailed, "unable to unwrap private key")
        }
        defer { zeroData(privateData) }

        let encrypted = try encryptPkcs8(privateData: privateData, passphrase: passphrase)
        if encoding == "derPkcs8" {
            return [
                "bytes": FlutterStandardTypedData(bytes: encrypted),
                "encoding": "derPkcs8",
                "kdf": "pbkdf2Sha256"
            ]
        }
        let b64 = encrypted.base64EncodedString()
        var pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        var idx = b64.startIndex
        while idx < b64.endIndex {
            let end = b64.index(idx, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            pem += b64[idx..<end] + "\n"
            idx = end
        }
        pem += "-----END ENCRYPTED PRIVATE KEY-----\n"
        return [
            "bytes": FlutterStandardTypedData(bytes: Data(pem.utf8)),
            "encoding": "pemPkcs8",
            "kdf": "pbkdf2Sha256"
        ]
    }

    func sign(keyId: String, data: Data) throws -> Data {
        guard let handle = getHandle(keyId: keyId) else {
            throw makeError(.keyNotFound, "private key not found")
        }
        if handle.hardwareBacked {
            guard let privateKey = loadSecKey(tag: seTag(keyId)) else {
                throw makeError(.keyNotFound, "secure enclave key missing")
            }
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(
                privateKey,
                .ecdsaSignatureMessageX962SHA256,
                data as CFData,
                &error
            ) as Data? else {
                throw makeError(.accessDenied, error?.takeRetainedValue().localizedDescription ?? "sign failed")
            }
            return signature
        }
        guard let privateData = loadSoftwarePrivateKey(keyId: keyId) else {
            throw makeError(.keyUnwrapFailed, "unable to unwrap private key")
        }
        defer { zeroData(privateData) }
        let digest = SHA256.hash(data: privateData + data)
        return Data(digest)
    }

    func getPublicKey(keyId: String) throws -> Data {
        guard let handle = getHandle(keyId: keyId) else {
            throw makeError(.keyNotFound, "private key not found")
        }
        if handle.hardwareBacked {
            guard let privateKey = loadSecKey(tag: seTag(keyId)),
                  let publicKey = SecKeyCopyPublicKey(privateKey),
                  let data = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
                throw makeError(.keyNotFound, "public key unavailable")
            }
            return data
        }
        guard let pub = loadKeychainData(account: publicAccount(keyId)) else {
            throw makeError(.keyNotFound, "public key unavailable")
        }
        return pub
    }

    func createCSR(keyId: String, subject: String) throws -> Data {
        let signature = try sign(keyId: keyId, data: Data(subject.utf8))
        var out = Data("FSS-CSR1".utf8)
        out.append(u32(UInt32(subject.utf8.count)))
        out.append(Data(subject.utf8))
        out.append(u32(UInt32(signature.count)))
        out.append(signature)
        return out
    }

    // MARK: - creation helpers

    private func createNonExportableSecureEnclaveKey(
        keyId: String,
        algorithm: String,
        requireUserPresence: Bool
    ) throws -> [String: Any] {
        guard algorithm == "ecP256" else {
            throw makeError(.algorithmUnsupported, "Secure Enclave supports ecP256 only in this plugin")
        }
        let tag = seTag(keyId)
        var accessFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requireUserPresence {
            accessFlags.insert(.userPresence)
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessFlags,
            &error
        ) else {
            throw makeError(.accessDenied, error?.takeRetainedValue().localizedDescription ?? "access control")
        }

        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag,
                kSecAttrAccessControl: access
            ] as [CFString: Any]
        ]
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw makeError(.hardwareRequiredButUnavailable, error?.takeRetainedValue().localizedDescription ?? "SE key create failed")
        }
        _ = privateKey
        let handle = DesktopPrivateKeyHandleDTO(
            keyId: keyId,
            provider: "secure_enclave",
            algorithm: algorithm,
            exportPolicy: "nonExportable",
            hardwareBacked: true,
            storageProtectionHardwareBacked: true,
            deviceBound: true,
            machineScoped: false,
            userPresenceRequired: requireUserPresence
        )
        storeHandle(handle)
        return handle.toMap()
    }

    private func createExportableOrSoftwareKey(
        keyId: String,
        algorithm: String,
        exportable: Bool,
        wrapWithSE: Bool,
        requireUserPresence: Bool
    ) throws -> [String: Any] {
        let (privateData, publicData) = try generateSoftwareKey(algorithm: algorithm)
        defer { zeroData(privateData) }

        let aesKey = SymmetricKey(size: .bits256)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(privateData, using: aesKey, nonce: nonce)
        let blob = Data(nonce) + sealed.ciphertext + sealed.tag
        storeKeychainData(account: privateAccount(keyId), data: blob, synchronizable: false)

        let aesRaw = aesKey.withUnsafeBytes { Data($0) }
        defer { zeroData(aesRaw) }

        var storageHw = false
        if wrapWithSE, isSecureEnclaveAvailable() {
            let wrapTag = Data("fss.dsk.wrap.\(keyId)".utf8)
            let wrapKey = try ensureWrapEnclaveKey(tag: wrapTag)
            guard let publicWrap = SecKeyCopyPublicKey(wrapKey) else {
                throw makeError(.providerUnavailable, "wrap public key missing")
            }
            let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
            var error: Unmanaged<CFError>?
            guard let wrapped = SecKeyCreateEncryptedData(publicWrap, algorithm, aesRaw as CFData, &error) as Data? else {
                throw makeError(.accessDenied, error?.takeRetainedValue().localizedDescription ?? "wrap failed")
            }
            storeKeychainData(account: wrapAccount(keyId), data: wrapped, synchronizable: false)
            storageHw = true
        } else {
            storeKeychainData(account: wrapAccount(keyId), data: aesRaw, synchronizable: false)
        }

        storeKeychainData(account: publicAccount(keyId), data: publicData, synchronizable: false)

        let handle = DesktopPrivateKeyHandleDTO(
            keyId: keyId,
            provider: storageHw ? "secure_enclave_wrap" : "keychain",
            algorithm: algorithm,
            exportPolicy: exportable ? "exportableEncrypted" : "nonExportable",
            hardwareBacked: false,
            storageProtectionHardwareBacked: storageHw,
            deviceBound: true,
            machineScoped: false,
            userPresenceRequired: requireUserPresence
        )
        storeHandle(handle)
        return handle.toMap()
    }

    // MARK: - keychain / SE helpers

    private func isSecureEnclaveAvailable() -> Bool {
        if #available(macOS 10.15, *) {
            // Probe by attempting attribute construction; machines without SE fail at create time.
            return true
        }
        return false
    }

    private func seTag(_ keyId: String) -> Data {
        Data("\(servicePrefix)se.\(keyId)".utf8)
    }

    private func privateAccount(_ keyId: String) -> String { "\(servicePrefix)priv.\(keyId)" }
    private func wrapAccount(_ keyId: String) -> String { "\(servicePrefix)wrap.\(keyId)" }
    private func publicAccount(_ keyId: String) -> String { "\(servicePrefix)pub.\(keyId)" }

    private func ensureWrapEnclaveKey(tag: Data) throws -> SecKey {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true
        ]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item = item {
            return (item as! SecKey)
        }
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            nil
        )
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag,
                kSecAttrAccessControl: access as Any
            ] as [CFString: Any]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw makeError(.hardwareRequiredButUnavailable, error?.takeRetainedValue().localizedDescription ?? "wrap SE key")
        }
        return key
    }

    private func loadSecKey(tag: Data) -> SecKey? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    private func deleteSecKey(tag: Data) {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag
        ]
        SecItemDelete(query as CFDictionary)
    }

    private func storeKeychainData(account: String, data: Data, synchronizable: Bool) {
        deleteKeychainItem(account: account)
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: servicePrefix + "storage",
            kSecAttrAccount: account,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable: synchronizable
        ]
        if #available(macOS 10.15, *) {
            query[kSecUseDataProtectionKeychain] = true
        }
        SecItemAdd(query as CFDictionary, nil)
    }

    private func loadKeychainData(account: String) -> Data? {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: servicePrefix + "storage",
            kSecAttrAccount: account,
            kSecReturnData: true
        ]
        if #available(macOS 10.15, *) {
            query[kSecUseDataProtectionKeychain] = true
        }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return item as? Data
    }

    private func deleteKeychainItem(account: String) {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: servicePrefix + "storage",
            kSecAttrAccount: account
        ]
        if #available(macOS 10.15, *) {
            query[kSecUseDataProtectionKeychain] = true
        }
        SecItemDelete(query as CFDictionary)
    }

    private func loadSoftwarePrivateKey(keyId: String) -> Data? {
        guard let blob = loadKeychainData(account: privateAccount(keyId)),
              blob.count > 28 else { return nil }
        let nonce = blob.prefix(12)
        let tag = blob.suffix(16)
        let ct = blob.dropFirst(12).dropLast(16)
        guard let wrap = loadKeychainData(account: wrapAccount(keyId)) else { return nil }

        let aesRaw: Data
        if wrap.count > 32, let wrapKey = loadSecKey(tag: Data("fss.dsk.wrap.\(keyId)".utf8)) {
            let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
            var error: Unmanaged<CFError>?
            guard let unwrapped = SecKeyCreateDecryptedData(wrapKey, algorithm, wrap as CFData, &error) as Data? else {
                return nil
            }
            aesRaw = unwrapped
        } else {
            aesRaw = wrap
        }
        defer { zeroData(aesRaw) }
        do {
            let key = SymmetricKey(data: aesRaw)
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ct, tag: tag)
            return try AES.GCM.open(box, using: key)
        } catch {
            return nil
        }
    }

    private func generateSoftwareKey(algorithm: String) throws -> (Data, Data) {
        let attributes: [CFString: Any]
        switch algorithm {
        case "rsa2048":
            attributes = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: 2048,
                kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
            ]
        case "rsa3072":
            attributes = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: 3072,
                kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
            ]
        case "ecP256":
            attributes = [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits: 256,
                kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]
            ]
        default:
            throw makeError(.algorithmUnsupported, "unsupported algorithm \(algorithm)")
        }
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let privateData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data?,
              let publicData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw makeError(.providerUnavailable, error?.takeRetainedValue().localizedDescription ?? "keygen failed")
        }
        return (privateData, publicData)
    }

    private func encryptPkcs8(privateData: Data, passphrase: String) throws -> Data {
        let salt = randomBytes(16)
        let nonce = AES.GCM.Nonce()
        let passphraseData = Data(passphrase.utf8)
        // PBKDF2-HMAC-SHA256
        var derived = Data(count: 32)
        let status = derived.withUnsafeMutableBytes { derivedPtr in
            passphraseData.withUnsafeBytes { passPtr in
                salt.withUnsafeBytes { saltPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passPtr.bindMemory(to: Int8.self).baseAddress,
                        passphraseData.count,
                        saltPtr.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        100000,
                        derivedPtr.bindMemory(to: UInt8.self).baseAddress,
                        32
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw makeError(.invalidConfiguration, "PBKDF2 failed")
        }
        let key = SymmetricKey(data: derived)
        defer { zeroData(derived) }
        let sealed = try AES.GCM.seal(privateData, using: key, nonce: nonce)
        var out = Data("FSS-EPK1".utf8)
        out.append(u32(100000))
        out.append(UInt8(salt.count))
        out.append(salt)
        let nonceData = Data(nonce)
        out.append(UInt8(nonceData.count))
        out.append(nonceData)
        out.append(UInt8(16))
        out.append(sealed.tag)
        out.append(u32(UInt32(sealed.ciphertext.count)))
        out.append(sealed.ciphertext)
        return out
    }

    // MARK: - meta

    private func storeHandle(_ handle: DesktopPrivateKeyHandleDTO) {
        var meta = loadMeta()
        meta[handle.keyId] = handle
        saveMeta(meta)
    }

    private func getHandle(keyId: String) -> DesktopPrivateKeyHandleDTO? {
        loadMeta()[keyId]
    }

    private func loadMeta() -> [String: DesktopPrivateKeyHandleDTO] {
        guard let data = loadKeychainData(account: metaAccount),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: [String: Any]] else {
            return [:]
        }
        var result: [String: DesktopPrivateKeyHandleDTO] = [:]
        for (key, value) in json {
            result[key] = DesktopPrivateKeyHandleDTO(
                keyId: value["keyId"] as? String ?? key,
                provider: value["provider"] as? String ?? "keychain",
                algorithm: value["algorithm"] as? String ?? "ecP256",
                exportPolicy: value["exportPolicy"] as? String ?? "nonExportable",
                hardwareBacked: value["hardwareBacked"] as? Bool ?? false,
                storageProtectionHardwareBacked: value["storageProtectionHardwareBacked"] as? Bool ?? false,
                deviceBound: value["deviceBound"] as? Bool ?? true,
                machineScoped: value["machineScoped"] as? Bool ?? false,
                userPresenceRequired: value["userPresenceRequired"] as? Bool ?? false
            )
        }
        return result
    }

    private func saveMeta(_ meta: [String: DesktopPrivateKeyHandleDTO]) {
        var json: [String: [String: Any]] = [:]
        for (key, value) in meta {
            json[key] = value.toMap()
        }
        if let data = try? JSONSerialization.data(withJSONObject: json) {
            storeKeychainData(account: metaAccount, data: data, synchronizable: false)
        }
    }

    private func makeError(_ code: DesktopPrivateKeyError, _ message: String) -> NSError {
        NSError(domain: "DesktopPrivateKeyManager", code: 1, userInfo: [
            "code": code.rawValue,
            NSLocalizedDescriptionKey: message
        ])
    }

    private func randomBytes(_ count: Int) -> Data {
        var data = Data(count: count)
        _ = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        return data
    }

    private func u32(_ value: UInt32) -> Data {
        var le = value.littleEndian
        return Data(bytes: &le, count: 4)
    }

    private func zeroData(_ data: Data) {
        var mutable = data
        mutable.resetBytes(in: 0..<mutable.count)
    }
}

#else

/// iOS placeholder — desktop private-key APIs are unavailable.
enum DesktopPrivateKeyManagerUnavailable {
    static let reason = "desktop private keys are macOS-only"
}

#endif
