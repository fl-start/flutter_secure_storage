import Foundation
import Security
import CryptoKit
import LocalAuthentication

import CommonCrypto
#if os(iOS)
import Flutter
#else
import FlutterMacOS
#endif

/// Apple platforms private-key manager (iOS Secure Enclave / Keychain, macOS SE / Keychain).
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
            #if os(iOS)
            "platform": "ios",
#else
            "platform": "macos",
#endif
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
            throw makeError(.invalidConfiguration, "machineScoped is not supported on Apple private keys")
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

    func importPrivateKey(args: [String: Any], encryptedKey: Data) throws -> [String: Any] {
        guard let keyId = args["keyId"] as? String, !keyId.isEmpty else {
            throw makeError(.invalidConfiguration, "keyId required")
        }
        if keyId.contains("..") || keyId.contains("\\") {
            throw makeError(.invalidConfiguration, "unsafe keyId")
        }
        if getHandle(keyId: keyId) != nil {
            throw makeError(.keyAlreadyExists, "private key already exists")
        }
        if args["machineScoped"] as? Bool == true {
            throw makeError(.invalidConfiguration, "machineScoped is not supported on Apple private keys")
        }
        var passphrase = args["passphrase"] as? String ?? ""
        if passphrase.isEmpty, let bytes = (args["passphraseBytes"] as? FlutterStandardTypedData)?.data {
            passphrase = String(data: bytes, encoding: .utf8) ?? ""
        }
        guard !passphrase.isEmpty else {
            throw makeError(.invalidExportPassphrase, "import passphrase must be non-empty")
        }

        var blob = encryptedKey
        if let pem = String(data: encryptedKey, encoding: .utf8),
           pem.contains("BEGIN ENCRYPTED PRIVATE KEY") {
            let body = pem
                .replacingOccurrences(of: "-----BEGIN ENCRYPTED PRIVATE KEY-----", with: "")
                .replacingOccurrences(of: "-----END ENCRYPTED PRIVATE KEY-----", with: "")
                .filter { !$0.isWhitespace }
            guard let decoded = Data(base64Encoded: body) else {
                throw makeError(.corruptRecord, "invalid PEM")
            }
            blob = decoded
        }

        let privateData = try decryptPkcs8(encrypted: blob, passphrase: passphrase)
        defer { zeroData(privateData) }

        let algorithm = args["algorithm"] as? String ?? inferAlgorithm(privateData: privateData)
        let exportPolicy = args["exportPolicy"] as? String ?? "exportableEncrypted"
        let requireUserPresence = args["requireUserPresence"] as? Bool ?? false
        let protection = args["protection"] as? String ?? "platformDefault"
        let wrapWithSE = isSecureEnclaveAvailable()
            && (protection == "hardwareBackedPreferred" || protection == "hardwareBackedRequired" || protection == "platformDefault")

        let attrs: [CFString: Any] = [
            kSecAttrKeyType: algorithm.hasPrefix("rsa") ? kSecAttrKeyTypeRSA : kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: algorithm == "rsa3072" ? 3072 : (algorithm == "rsa2048" ? 2048 : 256)
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(privateData as CFData, attrs as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw makeError(.corruptRecord, error?.takeRetainedValue().localizedDescription ?? "import parse failed")
        }

        let aesKey = SymmetricKey(size: .bits256)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(privateData, using: aesKey, nonce: nonce)
        let sealedBlob = Data(nonce) + sealed.ciphertext + sealed.tag
        storeKeychainData(account: privateAccount(keyId), data: sealedBlob, synchronizable: false)

        let aesRaw = aesKey.withUnsafeBytes { Data($0) }
        defer { zeroData(aesRaw) }
        var storageHw = false
        if wrapWithSE {
            let wrapTag = Data("fss.dsk.wrap.\(keyId)".utf8)
            let wrapKey = try ensureWrapEnclaveKey(tag: wrapTag)
            guard let publicWrap = SecKeyCopyPublicKey(wrapKey) else {
                throw makeError(.providerUnavailable, "wrap public key missing")
            }
            let wrapAlgorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
            guard let wrapped = SecKeyCreateEncryptedData(publicWrap, wrapAlgorithm, aesRaw as CFData, &error) as Data? else {
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
            exportPolicy: exportPolicy,
            hardwareBacked: false,
            storageProtectionHardwareBacked: storageHw,
            deviceBound: true,
            machineScoped: false,
            userPresenceRequired: requireUserPresence
        )
        storeHandle(handle)
        return ["handle": handle.toMap()]
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
        let keyType: CFString
        let keySize: Int
        let algorithm: SecKeyAlgorithm
        switch handle.algorithm {
        case "rsa2048":
            keyType = kSecAttrKeyTypeRSA
            keySize = 2048
            algorithm = .rsaSignatureMessagePKCS1v15SHA256
        case "rsa3072":
            keyType = kSecAttrKeyTypeRSA
            keySize = 3072
            algorithm = .rsaSignatureMessagePKCS1v15SHA256
        default:
            keyType = kSecAttrKeyTypeECSECPrimeRandom
            keySize = 256
            algorithm = .ecdsaSignatureMessageX962SHA256
        }
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: keyType,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: keySize
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(privateData as CFData, attrs as CFDictionary, &error) else {
            throw makeError(.keyUnwrapFailed, error?.takeRetainedValue().localizedDescription ?? "private key parse failed")
        }
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            throw makeError(.accessDenied, error?.takeRetainedValue().localizedDescription ?? "sign failed")
        }
        return signature
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
        #if targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
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
        let derived = try pbkdf2(passphrase: passphrase, salt: salt, iterations: 100000)
        defer { zeroData(derived) }
        let key = SymmetricKey(data: derived)
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

    private func decryptPkcs8(encrypted: Data, passphrase: String) throws -> Data {
        guard encrypted.count > 8 + 4 + 1, String(data: encrypted.prefix(8), encoding: .utf8) == "FSS-EPK1" else {
            throw makeError(.corruptRecord, "not FSS-EPK1")
        }
        var idx = encrypted.startIndex.advanced(by: 8)
        let iters = encrypted[idx..<idx.advanced(by: 4)].withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
        idx = idx.advanced(by: 4)
        let saltLen = Int(encrypted[idx]); idx = idx.advanced(by: 1)
        let salt = encrypted[idx..<idx.advanced(by: saltLen)]; idx = idx.advanced(by: saltLen)
        let nonceLen = Int(encrypted[idx]); idx = idx.advanced(by: 1)
        let nonceData = encrypted[idx..<idx.advanced(by: nonceLen)]; idx = idx.advanced(by: nonceLen)
        let tagLen = Int(encrypted[idx]); idx = idx.advanced(by: 1)
        let tag = encrypted[idx..<idx.advanced(by: tagLen)]; idx = idx.advanced(by: tagLen)
        let ctLen = Int(encrypted[idx..<idx.advanced(by: 4)].withUnsafeBytes { $0.load(as: UInt32.self).littleEndian })
        idx = idx.advanced(by: 4)
        let ct = encrypted[idx..<idx.advanced(by: ctLen)]

        let derived = try pbkdf2(passphrase: passphrase, salt: Data(salt), iterations: Int(iters))
        defer { zeroData(derived) }
        let key = SymmetricKey(data: derived)
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: Data(nonceData)),
            ciphertext: Data(ct),
            tag: Data(tag)
        )
        return try AES.GCM.open(box, using: key)
    }

    private func pbkdf2(passphrase: String, salt: Data, iterations: Int) throws -> Data {
        let passphraseData = Data(passphrase.utf8)
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
                        UInt32(iterations),
                        derivedPtr.bindMemory(to: UInt8.self).baseAddress,
                        32
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw makeError(.invalidConfiguration, "PBKDF2 failed")
        }
        return derived
    }

    private func inferAlgorithm(privateData: Data) -> String {
        if privateData.count > 500 {
            return privateData.count > 1200 ? "rsa3072" : "rsa2048"
        }
        return "ecP256"
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
