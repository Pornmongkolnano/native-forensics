// Standalone synthetic EFS probe. Secret material only arrives on stdin.
// Not a shipping product and intentionally absent from the Swift product graph.
#define NF_EFS_ENABLE_PFX_DIAGNOSTIC 1
#include "../../NativeEngine/EFSNativeContent.hpp"
#include <nlohmann/json.hpp>
#include <cerrno>
#include <csignal>
#include <iostream>
#include <memory>
#include <unistd.h>

namespace efs = nativeforensics::efs;
using Json = nlohmann::json;
constexpr size_t kProbeCiphertextLimit = 8 * 1024 * 1024;
bool exactRead(void *target, size_t count) {
    auto *bytes = static_cast<uint8_t *>(target);
    while (count) {
        const ssize_t received = ::read(STDIN_FILENO, bytes, count);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return false;
        bytes += received; count -= size_t(received);
    }
    return true;
}
uint64_t little64(const uint8_t *bytes) {
    uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index) result |= uint64_t(bytes[index]) << (index * 8);
    return result;
}
std::vector<uint8_t> readBytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    if (!exactRead(bytes.data(), bytes.size())) throw efs::Error("PROBE_TRUNCATED_INPUT");
    return bytes;
}
void exactWrite(const uint8_t *bytes, size_t count) {
    while (count) {
        const ssize_t written = ::write(STDOUT_FILENO, bytes, count);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) throw efs::Error("PROBE_OUTPUT_FAILED");
        bytes += written; count -= size_t(written);
    }
}
int matchingKeychainItems(CFTypeRef itemClass, CFStringRef attribute, CFTypeRef value, bool dataProtection = false, OSStatus *unavailable = nullptr) {
    const void *keys[] = {kSecClass, attribute, kSecMatchLimit, kSecReturnAttributes, kSecUseAuthenticationUI, kSecUseDataProtectionKeychain};
    const void *values[] = {itemClass, value, kSecMatchLimitAll, kCFBooleanTrue, kSecUseAuthenticationUIFail, dataProtection ? kCFBooleanTrue : kCFBooleanFalse};
    efs::CFObject<CFDictionaryRef> query(CFDictionaryCreate(kCFAllocatorDefault, keys, values, 6,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    CFTypeRef output = nullptr;
    const OSStatus status = SecItemCopyMatching(query.get(), &output);
    efs::CFObject<CFTypeRef> owned(output);
    if (status == errSecItemNotFound) return 0;
    if (status != errSecSuccess || !output || CFGetTypeID(output) != CFArrayGetTypeID()) {
        if (unavailable) { *unavailable = status; return -1; }
        throw efs::Error("PROBE_KEYCHAIN_OBSERVATION_UNAVAILABLE");
    }
    return int(CFArrayGetCount(static_cast<CFArrayRef>(output)));
}
struct SyntheticIdentityObservation {
    efs::CFObject<SecCertificateRef> certificate;
    efs::CFObject<CFDataRef> subject;
    efs::CFObject<CFDataRef> keyLabel;
    explicit SyntheticIdentityObservation(const std::vector<uint8_t> &bytes) {
        efs::CFObject<CFDataRef> data(CFDataCreate(kCFAllocatorDefault, bytes.data(), CFIndex(bytes.size())));
        certificate = efs::CFObject<SecCertificateRef>(SecCertificateCreateWithData(kCFAllocatorDefault, data.get()));
        if (!certificate.get()) throw efs::Error("PROBE_INVALID_PUBLIC_CERTIFICATE");
        CFStringRef commonName = nullptr;
        if (SecCertificateCopyCommonName(certificate.get(), &commonName) != errSecSuccess || !commonName)
            throw efs::Error("PROBE_NON_SYNTHETIC_CERTIFICATE");
        efs::CFObject<CFStringRef> name(commonName);
        std::array<char, 128> boundedName{};
        if (!CFStringGetCString(commonName, boundedName.data(), boundedName.size(), kCFStringEncodingUTF8) ||
            std::string(boundedName.data()).rfind("NF-EFS-SYNTHETIC-", 0) != 0)
            throw efs::Error("PROBE_NON_SYNTHETIC_CERTIFICATE");
        subject = efs::CFObject<CFDataRef>(SecCertificateCopyNormalizedSubjectSequence(certificate.get()));
        efs::CFObject<SecKeyRef> publicKey(SecCertificateCopyKey(certificate.get()));
        efs::CFObject<CFDictionaryRef> attributes(publicKey.get() ? SecKeyCopyAttributes(publicKey.get()) : nullptr);
        const CFTypeRef label = attributes.get() ? CFDictionaryGetValue(attributes.get(), kSecAttrApplicationLabel) : nullptr;
        if (!subject.get() || !label || CFGetTypeID(label) != CFDataGetTypeID())
            throw efs::Error("PROBE_KEYCHAIN_OBSERVATION_UNAVAILABLE");
        keyLabel = efs::CFObject<CFDataRef>(static_cast<CFDataRef>(CFRetain(label)));
    }
    Json protectionCounts() const {
        OSStatus certificateStatus = errSecSuccess, keyStatus = errSecSuccess;
        const int certificates = matchingKeychainItems(kSecClassCertificate, kSecAttrSubject, subject.get(), true, &certificateStatus);
        const int keys = matchingKeychainItems(kSecClassKey, kSecAttrApplicationLabel, keyLabel.get(), true, &keyStatus);
        if (certificates < 0 || keys < 0)
            return {{"available", false}, {"certificateStatus", certificateStatus}, {"keyStatus", keyStatus}};
        return {{"available", true}, {"certificates", certificates}, {"keys", keys}};
    }
    Json counts() const {
        return {{"certificates", matchingKeychainItems(kSecClassCertificate, kSecAttrSubject, subject.get())},
                {"keys", matchingKeychainItems(kSecClassKey, kSecAttrApplicationLabel, keyLabel.get())}};
    }
};
int main() {
    ::signal(SIGPIPE, SIG_IGN);
    Json report{{"schemaVersion", 1}, {"materializationMode", "in-memory-only"}, {"syntheticProbe", true}};
    std::unique_ptr<SyntheticIdentityObservation> identity;
    try {
        // Observable owned-buffer oracle for the SAME RAII primitive used by
        // Input.readChunk when a single read prefetches binary credential bytes.
        std::array<uint8_t, 4096> prefetched{};
        prefetched.fill(0x6d);
        { efs::ScopedWipe guard(prefetched.data(), prefetched.size()); }
        if (std::any_of(prefetched.begin(), prefetched.end(), [](uint8_t value) { return value != 0; }))
            throw efs::Error("PROBE_OWNED_BUFFER_WIPE_FAILED");
        prefetched.fill(0x37);
        try { efs::ScopedWipe guard(prefetched.data(), prefetched.size()); throw 1; }
        catch (int) {}
        if (std::any_of(prefetched.begin(), prefetched.end(), [](uint8_t value) { return value != 0; }))
            throw efs::Error("PROBE_OWNED_BUFFER_WIPE_FAILED");
        report["ownedBufferWipeChecks"] = 2;
        std::array<uint8_t, 40> header{};
        if (!exactRead(header.data(), 8)) throw efs::Error("PROBE_TRUNCATED_INPUT");
        const std::array<uint8_t, 8> observationMagic{'N', 'F', 'E', 'O', 0, 0, 0, 1};
        if (std::equal(observationMagic.begin(), observationMagic.end(), header.begin())) {
            std::array<uint8_t, 4> count{};
            if (!exactRead(count.data(), count.size())) throw efs::Error("PROBE_TRUNCATED_INPUT");
            const uint32_t length = efs::little32(count.data());
            if (length == 0 || length > 128 * 1024) throw efs::Error("PROBE_INPUT_LIMIT");
            identity = std::make_unique<SyntheticIdentityObservation>(readBytes(length));
            uint8_t extra = 0;
            if (::read(STDIN_FILENO, &extra, 1) != 0) throw efs::Error("PROBE_TRAILING_INPUT");
            report["status"] = "observed";
            report["keychainAfterProcess"] = identity->counts();
            report["dataProtectionAfterProcess"] = identity->protectionCounts();
            std::cout << report.dump() << '\n';
            return 0;
        }
        if (!exactRead(header.data() + 8, header.size() - 8)) throw efs::Error("PROBE_TRUNCATED_INPUT");
        const std::array<uint8_t, 8> derMagic{'N', 'F', 'E', 'D', 0, 0, 0, 1};
        const bool derProfile = std::equal(derMagic.begin(), derMagic.end(), header.begin());
        report["profile"] = derProfile ? "pkcs1-der" : "pfx-diagnostic";
        const std::array<uint8_t, 8> magic{'N', 'F', 'E', 'P', 0, 0, 0, 1};
        if (!derProfile && !std::equal(magic.begin(), magic.end(), header.begin())) throw efs::Error("PROBE_INVALID_FRAME");
        const uint32_t metadataLength = efs::little32(header.data() + 8), pfxLength = efs::little32(header.data() + 12),
            passwordLength = efs::little32(header.data() + 16), certificateLength = efs::little32(header.data() + 20);
        const uint64_t logicalLength = little64(header.data() + 24), ciphertextLength = little64(header.data() + 32);
        if (metadataLength > efs::kMetadataLimit || pfxLength > (derProfile ? efs::kPrivateKeyDERLimit : efs::kPFXLimit) || passwordLength > efs::kPasswordLimit ||
            (derProfile && passwordLength != 0) ||
            certificateLength > 128 * 1024 || ciphertextLength > kProbeCiphertextLimit || logicalLength > ciphertextLength ||
            ciphertextLength % efs::kUnitBytes || ciphertextLength != logicalLength + (efs::kUnitBytes - logicalLength % efs::kUnitBytes) % efs::kUnitBytes)
            throw efs::Error("PROBE_INPUT_LIMIT");
        const auto metadata = efs::parseMetadata(readBytes(metadataLength));
        efs::SecretBytes pfx(readBytes(pfxLength)), password(readBytes(passwordLength));
        const auto publicCertificate = readBytes(certificateLength);
        identity = std::make_unique<SyntheticIdentityObservation>(publicCertificate);
        report["keychainBefore"] = identity->counts();
        report["dataProtectionBefore"] = identity->protectionCounts();
        if (report["keychainBefore"] != Json{{"certificates", 0}, {"keys", 0}})
            throw efs::Error("PROBE_SYNTHETIC_IDENTITY_ALREADY_PRESENT");
        CC_SHA256_CTX digest;
        CC_SHA256_Init(&digest);
        {
            auto key = derProfile ? efs::FileKey::fromPKCS1(metadata, std::move(pfx), publicCertificate) :
                efs::FileKey::importAndUnwrapDiagnosticPFX(metadata, std::move(pfx), std::move(password));
            report["role"] = key.role == efs::Role::decryption ? "ddf" : "drf";
            uint64_t outputBytes = 0;
            for (uint64_t position = 0; position < ciphertextLength; position += efs::kUnitBytes) {
                std::array<uint8_t, efs::kUnitBytes> cipher{}, clear{};
                if (!exactRead(cipher.data(), cipher.size())) throw efs::Error("PROBE_TRUNCATED_INPUT");
                key.decryptUnit(cipher, position, clear);
                const size_t count = size_t(std::min<uint64_t>(efs::kUnitBytes, logicalLength - outputBytes));
                exactWrite(clear.data(), count);
                CC_SHA256_Update(&digest, clear.data(), CC_LONG(count));
                outputBytes += count;
                efs::wipe(clear.data(), clear.size());
            }
            uint8_t extra = 0;
            if (::read(STDIN_FILENO, &extra, 1) != 0) throw efs::Error("PROBE_TRAILING_INPUT");
            report["outputBytes"] = outputBytes;
        }
        std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> hash{};
        CC_SHA256_Final(hash.data(), &digest);
        constexpr char alphabet[] = "0123456789abcdef";
        std::string hex;
        for (uint8_t byte : hash) { hex.push_back(alphabet[byte >> 4]); hex.push_back(alphabet[byte & 15]); }
        report["outputSHA256"] = hex;
        report["status"] = "decrypted-observed-bytes";
        report["authenticatedPlaintext"] = false;
        report["keychainAfter"] = identity->counts();
        report["dataProtectionAfter"] = identity->protectionCounts();
        if (report["keychainAfter"] != report["keychainBefore"]) throw efs::Error("PROBE_KEYCHAIN_CHANGED");
        std::cerr << report.dump() << '\n';
        return 0;
    } catch (const efs::Error &error) {
        report["status"] = "rejected";
        report["code"] = error.code;
        if (identity) {
            try { report["keychainAfter"] = identity->counts(); report["dataProtectionAfter"] = identity->protectionCounts(); }
            catch (...) { report["keychainAfter"] = "unavailable"; }
        }
    } catch (...) {
        report["status"] = "rejected"; report["code"] = "PROBE_INTERNAL_ERROR";
    }
    std::cerr << report.dump() << '\n';
    return 1;
}
