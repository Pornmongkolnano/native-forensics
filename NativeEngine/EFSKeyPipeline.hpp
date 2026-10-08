// NativeForensics original, bounded EFS key/decryption component.
// This header is intentionally not wired into NFTSKEngine until its standalone
// primary-format, independent-cipher and keychain-state gates have passed.
#pragma once

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace nativeforensics::efs {
constexpr size_t kMetadataLimit = 256 * 1024;
constexpr size_t kPFXLimit = 512 * 1024;
constexpr size_t kPrivateKeyDERLimit = 64 * 1024;
constexpr size_t kCertificateDERLimit = 128 * 1024;
constexpr size_t kPasswordLimit = 4096;
constexpr size_t kRecipientLimit = 64;
constexpr size_t kUnitBytes = 512;
constexpr uint32_t kAES256 = 0x6610;

struct Error : std::runtime_error {
    std::string code;
    explicit Error(std::string value) : std::runtime_error("EFS operation rejected"), code(std::move(value)) {}
};
inline void wipe(void *address, size_t count) noexcept {
    volatile uint8_t *cursor = static_cast<volatile uint8_t *>(address);
    while (count--) *cursor++ = 0;
}
class ScopedWipe {
    void *address;
    size_t count;
public:
    ScopedWipe(void *value, size_t length) noexcept : address(value), count(length) {}
    ScopedWipe(const ScopedWipe &) = delete;
    ScopedWipe &operator=(const ScopedWipe &) = delete;
    ~ScopedWipe() { wipe(address, count); }
};
class SecretBytes {
    std::vector<uint8_t> value;
public:
    SecretBytes() = default;
    explicit SecretBytes(std::vector<uint8_t> bytes) : value(std::move(bytes)) {}
    SecretBytes(const SecretBytes &) = delete;
    SecretBytes &operator=(const SecretBytes &) = delete;
    SecretBytes(SecretBytes &&other) noexcept : value(std::move(other.value)) {}
    SecretBytes &operator=(SecretBytes &&other) noexcept {
        if (this != &other) { clear(); value = std::move(other.value); }
        return *this;
    }
    ~SecretBytes() { clear(); }
    void clear() noexcept { if (!value.empty()) wipe(value.data(), value.size()); value.clear(); }
    const uint8_t *data() const noexcept { return value.data(); }
    uint8_t *data() noexcept { return value.data(); }
    size_t size() const noexcept { return value.size(); }
};
template <typename T> class CFObject {
    T value = nullptr;
public:
    CFObject() = default;
    explicit CFObject(T item) : value(item) {}
    CFObject(const CFObject &) = delete;
    CFObject &operator=(const CFObject &) = delete;
    CFObject(CFObject &&other) noexcept : value(std::exchange(other.value, nullptr)) {}
    CFObject &operator=(CFObject &&other) noexcept {
        if (this != &other) { if (value) CFRelease(value); value = std::exchange(other.value, nullptr); }
        return *this;
    }
    ~CFObject() { if (value) CFRelease(value); }
    T get() const noexcept { return value; }
};

inline uint32_t little32(const uint8_t *value) {
    return uint32_t(value[0]) | uint32_t(value[1]) << 8 | uint32_t(value[2]) << 16 | uint32_t(value[3]) << 24;
}
inline void storeLittle64(uint8_t *value, uint64_t number) {
    for (unsigned byte = 0; byte < 8; ++byte) value[byte] = uint8_t(number >> (byte * 8));
}
struct Range {
    size_t start = 0, length = 0;
    size_t end() const noexcept { return start + length; }
};
inline Range checkedRange(size_t start, size_t length, size_t limit) {
    if (start > limit || length > limit - start) throw Error("EFS_INVALID_METADATA");
    return {start, length};
}
inline bool overlap(Range left, Range right) {
    return left.length && right.length && left.start < right.end() && right.start < left.end();
}
inline void validateFields(size_t fixedHeader, size_t limit, std::vector<Range> fields) {
    std::sort(fields.begin(), fields.end(), [](Range a, Range b) { return a.start < b.start; });
    size_t covered = fixedHeader;
    for (Range field : fields) {
        checkedRange(field.start, field.length, limit);
        if (!field.length || field.start < covered || field.start - covered > 8) throw Error("EFS_INVALID_METADATA");
        covered = field.end();
    }
    if (covered > limit || limit - covered > 8) throw Error("EFS_INVALID_METADATA");
}
enum class Role { decryption, recovery };
struct Recipient {
    Role role;
    std::array<uint8_t, CC_SHA1_DIGEST_LENGTH> certificateThumbprint{};
    std::vector<uint8_t> wrappedKey;
};
struct Metadata {
    std::vector<Recipient> recipients;
    std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> sha256{};
};

// The supported $EFS profile uses the Microsoft metadata fixed84 header and
// EFS_Version2. Relative offsets at each
// nesting level. Never reinterpret an unaligned image pointer as a C struct.
inline Metadata parseMetadata(const std::vector<uint8_t> &bytes) {
    if (bytes.size() < 12 || bytes.size() > kMetadataLimit) throw Error("EFS_INVALID_METADATA");
    if (little32(bytes.data() + 8) != 2 && little32(bytes.data() + 8) != 3) throw Error("EFS_UNSUPPORTED_VERSION");
    if (bytes.size() < 84 || little32(bytes.data()) != bytes.size()) throw Error("EFS_INVALID_METADATA");
    Metadata result;
    std::vector<Range> arrays;
    for (unsigned which = 0; which < 2; ++which) {
        const uint32_t offset = little32(bytes.data() + 64 + which * 4);
        if (!offset) continue;
        if (offset < 84) throw Error("EFS_INVALID_METADATA");
        checkedRange(offset, 4, bytes.size());
        const uint32_t count = little32(bytes.data() + offset);
        if (!count || count > kRecipientLimit || count > kRecipientLimit - result.recipients.size())
            throw Error("EFS_RECIPIENT_LIMIT");
        size_t cursor = offset + 4;
        for (uint32_t entry = 0; entry < count; ++entry) {
            checkedRange(cursor, 20, bytes.size());
            const uint32_t fieldLength = little32(bytes.data() + cursor);
            if (fieldLength < 20) throw Error("EFS_INVALID_METADATA");
            checkedRange(cursor, fieldLength, bytes.size());
            const uint32_t credentialOffset = little32(bytes.data() + cursor + 4);
            const uint32_t wrappedLength = little32(bytes.data() + cursor + 8);
            const uint32_t wrappedOffset = little32(bytes.data() + cursor + 12);
            if (little32(bytes.data() + cursor + 16) != 0) throw Error("EFS_UNSUPPORTED_KEY_WRAPPING");
            if (credentialOffset < 20 || wrappedOffset < 20 || (wrappedLength != 128 && wrappedLength != 256 && wrappedLength != 512))
                throw Error("EFS_UNSUPPORTED_RECIPIENT");
            checkedRange(credentialOffset, 28, fieldLength);
            const uint8_t *credential = bytes.data() + cursor + credentialOffset;
            const uint32_t credentialLength = little32(credential);
            if (credentialLength < 28) throw Error("EFS_INVALID_METADATA");
            const Range credentialRange = checkedRange(credentialOffset, credentialLength, fieldLength);
            const Range wrappedRange = checkedRange(wrappedOffset, wrappedLength, fieldLength);
            validateFields(20, fieldLength, {credentialRange, wrappedRange});
            if (little32(credential + 8) != 3) throw Error("EFS_UNSUPPORTED_CREDENTIAL");
            const uint32_t headerLength = little32(credential + 12);
            const uint32_t headerOffset = little32(credential + 16);
            if (headerLength < 20 || headerOffset < 28) throw Error("EFS_INVALID_METADATA");
            checkedRange(headerOffset, headerLength, credentialLength);
            const uint8_t *header = credential + headerOffset;
            const uint32_t thumbprintOffset = little32(header);
            const uint32_t thumbprintLength = little32(header + 4);
            if (thumbprintLength != CC_SHA1_DIGEST_LENGTH || thumbprintOffset < 20)
                throw Error("EFS_UNSUPPORTED_RECIPIENT");
            // Offsets for the actual digest are relative to the thumbprint
            // header, while the header itself is relative to the credential.
            checkedRange(thumbprintOffset, thumbprintLength, headerLength);
            std::vector<Range> certificateFields{{thumbprintOffset, thumbprintLength}};
            std::vector<Range> credentialFields{{headerOffset, headerLength}};
            const uint32_t sidOffset = little32(credential + 4);
            // Packed revision1 RPC_SID is independently observed in the public
            // Windows NPS corpus:8-byte fixed header +count little-endian DWORDs.
            // The SID is used only to validate a nonoverlapping metadata region.
            if (sidOffset) {
                if (sidOffset < 28) throw Error("EFS_INVALID_METADATA");
                checkedRange(sidOffset, 8, credentialLength);
                const uint8_t *sid = credential + sidOffset;
                if (sid[0] != 1 || sid[1] > 15) throw Error("EFS_INVALID_METADATA");
                credentialFields.push_back(checkedRange(sidOffset, 8 + size_t(sid[1]) * 4, credentialLength));
            }
            // Names are not trusted, disclosed or used in recipient selection.
            // Validate every advertised UTF-16 name's terminator without
            // normalizing or interpreting its contents.
            for (size_t nameField : {size_t(8), size_t(12), size_t(16)}) {
                const uint32_t nameOffset = little32(header + nameField);
                if (!nameOffset) continue;
                if (nameOffset < 20 || nameOffset % 2 || nameOffset > headerLength)
                    throw Error("EFS_INVALID_METADATA");
                size_t position = nameOffset;
                bool terminated = false;
                for (; position + 1 < headerLength; position += 2)
                    if (header[position] == 0 && header[position + 1] == 0) { terminated = true; break; }
                if (!terminated) throw Error("EFS_INVALID_METADATA");
                certificateFields.push_back({nameOffset, position + 2 - nameOffset});
            }
            if ((little32(header + 8) == 0) != (little32(header + 12) == 0)) throw Error("EFS_INVALID_METADATA");
            validateFields(20, headerLength, std::move(certificateFields));
            validateFields(28, credentialLength, std::move(credentialFields));
            Recipient recipient{which == 0 ? Role::decryption : Role::recovery};
            std::copy_n(header + thumbprintOffset, CC_SHA1_DIGEST_LENGTH, recipient.certificateThumbprint.begin());
            recipient.wrappedKey.assign(bytes.begin() + cursor + wrappedOffset, bytes.begin() + cursor + wrappedOffset + wrappedLength);
            result.recipients.push_back(std::move(recipient));
            cursor += fieldLength;
        }
        const Range array{offset, cursor - offset};
        for (Range previous : arrays) if (overlap(previous, array)) throw Error("EFS_INVALID_METADATA");
        arrays.push_back(array);
    }
    if (result.recipients.empty()) throw Error("EFS_NO_RECIPIENT");
    validateFields(84, bytes.size(), std::move(arrays));
    CC_SHA256(bytes.data(), CC_LONG(bytes.size()), result.sha256.data());
    return result;
}

struct DERNode { uint8_t tag; Range content; size_t end; };
inline DERNode derNode(const uint8_t *bytes, size_t size, size_t offset) {
    if (offset >= size || size - offset < 2) throw Error("EFS_INVALID_CERTIFICATE");
    const uint8_t tag = bytes[offset++];
    if ((tag & 31) == 31) throw Error("EFS_INVALID_CERTIFICATE");
    const uint8_t first = bytes[offset++];
    size_t length = first;
    if (first & 0x80) {
        const size_t count = first & 0x7f;
        if (!count || count > sizeof(size_t) || count > size - offset || bytes[offset] == 0)
            throw Error("EFS_INVALID_CERTIFICATE");
        length = 0;
        for (size_t index = 0; index < count; ++index) {
            if (length > (std::numeric_limits<size_t>::max() >> 8)) throw Error("EFS_INVALID_CERTIFICATE");
            length = (length << 8) | bytes[offset++];
        }
        if (length < 128) throw Error("EFS_INVALID_CERTIFICATE");
    }
    if (length > size - offset) throw Error("EFS_INVALID_CERTIFICATE");
    return {tag, {offset, length}, offset + length};
}
inline bool matchesDER(const uint8_t *bytes, DERNode node, const std::vector<uint8_t> &expected) {
    return node.tag == 6 && node.content.length == expected.size() &&
        std::equal(expected.begin(), expected.end(), bytes + node.content.start);
}
inline std::pair<bool, bool> certificateRoles(CFDataRef certificate) {
    const uint8_t *bytes = CFDataGetBytePtr(certificate);
    const size_t size = size_t(CFDataGetLength(certificate));
    if (!size || size > 128 * 1024) throw Error("EFS_INVALID_CERTIFICATE");
    const DERNode top = derNode(bytes, size, 0);
    if (top.tag != 0x30 || top.end != size) throw Error("EFS_INVALID_CERTIFICATE");
    const DERNode tbs = derNode(bytes, top.end, top.content.start);
    if (tbs.tag != 0x30) throw Error("EFS_INVALID_CERTIFICATE");
    const std::vector<uint8_t> ekuOID{0x55, 0x1d, 0x25};
    const std::vector<uint8_t> ddfOID{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x04};
    const std::vector<uint8_t> drfOID{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x04, 0x01};
    bool foundExtensions = false, foundEKU = false, ddf = false, drf = false;
    size_t fields = 0;
    for (size_t cursor = tbs.content.start; cursor < tbs.end;) {
        if (++fields > 16) throw Error("EFS_INVALID_CERTIFICATE");
        const DERNode field = derNode(bytes, tbs.end, cursor); cursor = field.end;
        if (field.tag != 0xa3) continue;
        if (foundExtensions) throw Error("EFS_INVALID_CERTIFICATE");
        foundExtensions = true;
        const DERNode extensions = derNode(bytes, field.end, field.content.start);
        if (extensions.tag != 0x30 || extensions.end != field.end) throw Error("EFS_INVALID_CERTIFICATE");
        size_t extensionCount = 0;
        for (size_t extCursor = extensions.content.start; extCursor < extensions.end;) {
            if (++extensionCount > 64) throw Error("EFS_INVALID_CERTIFICATE");
            const DERNode extension = derNode(bytes, extensions.end, extCursor); extCursor = extension.end;
            if (extension.tag != 0x30) throw Error("EFS_INVALID_CERTIFICATE");
            const DERNode oid = derNode(bytes, extension.end, extension.content.start);
            if (oid.tag != 6) throw Error("EFS_INVALID_CERTIFICATE");
            size_t valueCursor = oid.end;
            DERNode value = derNode(bytes, extension.end, valueCursor);
            if (value.tag == 1) {
                if (value.content.length != 1 || (bytes[value.content.start] != 0 && bytes[value.content.start] != 0xff))
                    throw Error("EFS_INVALID_CERTIFICATE");
                valueCursor = value.end; value = derNode(bytes, extension.end, valueCursor);
            }
            if (value.tag != 4 || value.end != extension.end) throw Error("EFS_INVALID_CERTIFICATE");
            if (!matchesDER(bytes, oid, ekuOID)) continue;
            if (foundEKU) throw Error("EFS_INVALID_CERTIFICATE");
            foundEKU = true;
            const DERNode purposes = derNode(bytes, value.end, value.content.start);
            if (purposes.tag != 0x30 || purposes.end != value.end) throw Error("EFS_INVALID_CERTIFICATE");
            size_t purposeCount = 0;
            for (size_t purposeCursor = purposes.content.start; purposeCursor < purposes.end;) {
                if (++purposeCount > 64) throw Error("EFS_INVALID_CERTIFICATE");
                const DERNode purpose = derNode(bytes, purposes.end, purposeCursor); purposeCursor = purpose.end;
                if (purpose.tag != 6) throw Error("EFS_INVALID_CERTIFICATE");
                ddf |= matchesDER(bytes, purpose, ddfOID); drf |= matchesDER(bytes, purpose, drfOID);
            }
        }
    }
    return {ddf, drf};
}

class FileKey {
    SecretBytes bytes;
public:
    std::array<uint8_t, CC_SHA1_DIGEST_LENGTH> certificateThumbprint{};
    std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> metadataSHA256{};
    Role role = Role::decryption;
    explicit FileKey(SecretBytes value) : bytes(std::move(value)) {}
    FileKey(const FileKey &) = delete;
    FileKey &operator=(const FileKey &) = delete;
    FileKey(FileKey &&) = default;
    FileKey &operator=(FileKey &&) = default;

    static void collectCandidates(const Metadata &metadata, SecKeyRef privateKey, SecCertificateRef certificate,
                                  std::vector<FileKey> &candidates) {
        CFObject<CFDictionaryRef> attributes(SecKeyCopyAttributes(privateKey));
        if (!attributes.get()) throw Error("EFS_KEY_IDENTITY_INVALID");
        const CFTypeRef keyType = CFDictionaryGetValue(attributes.get(), kSecAttrKeyType);
        const CFTypeRef keyClass = CFDictionaryGetValue(attributes.get(), kSecAttrKeyClass);
        if (!keyType || !CFEqual(keyType, kSecAttrKeyTypeRSA)) throw Error("EFS_UNSUPPORTED_PRIVATE_KEY_TYPE");
        if (!keyClass || !CFEqual(keyClass, kSecAttrKeyClassPrivate)) throw Error("EFS_UNSUPPORTED_PRIVATE_KEY_CLASS");
        // Apple SecKeyCopyAttributes synthesizes IsPermanent:true for
        // local RSA keys, including memory-only imports; it is not a
        // keychain lookup. Persistence is prevented by the explicit import
        // option, with generated-identity before/after observations in tests.
        const size_t blockSize = SecKeyGetBlockSize(privateKey);
        if ((blockSize != 128 && blockSize != 256 && blockSize != 512) || !SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeDecrypt, kSecKeyAlgorithmRSAEncryptionPKCS1))
            throw Error("EFS_UNSUPPORTED_PRIVATE_KEY");
        CFObject<CFDataRef> certificateData(SecCertificateCopyData(certificate));
        if (!certificateData.get()) throw Error("EFS_KEY_IDENTITY_INVALID");
        std::array<uint8_t, CC_SHA1_DIGEST_LENGTH> thumbprint{};
        CC_SHA1(CFDataGetBytePtr(certificateData.get()), CC_LONG(CFDataGetLength(certificateData.get())), thumbprint.data());
        const auto purposes = certificateRoles(certificateData.get());
        CFObject<SecKeyRef> certificatePublicKey(SecCertificateCopyKey(certificate));
        CFObject<SecKeyRef> derivedPublicKey(SecKeyCopyPublicKey(privateKey));
        CFObject<CFDictionaryRef> publicAttributes(certificatePublicKey.get() ? SecKeyCopyAttributes(certificatePublicKey.get()) : nullptr);
        const CFTypeRef certificateKeyType = publicAttributes.get() ? CFDictionaryGetValue(publicAttributes.get(), kSecAttrKeyType) : nullptr;
        if (!certificateKeyType || !CFEqual(certificateKeyType, kSecAttrKeyTypeRSA)) throw Error("EFS_UNSUPPORTED_CERTIFICATE_KEY");
        CFErrorRef rawCertificateError = nullptr, rawDerivedError = nullptr;
        CFObject<CFDataRef> certificatePublicData(SecKeyCopyExternalRepresentation(certificatePublicKey.get(), &rawCertificateError));
        CFObject<CFErrorRef> certificateError(rawCertificateError);
        CFObject<CFDataRef> derivedPublicData(derivedPublicKey.get() ? SecKeyCopyExternalRepresentation(derivedPublicKey.get(), &rawDerivedError) : nullptr);
        CFObject<CFErrorRef> derivedError(rawDerivedError);
        if (!certificatePublicData.get() || !derivedPublicData.get() || !CFEqual(certificatePublicData.get(), derivedPublicData.get()))
            throw Error("EFS_CERTIFICATE_PRIVATE_KEY_MISMATCH");
        for (const Recipient &recipient : metadata.recipients) {
            if (recipient.certificateThumbprint != thumbprint) continue;
            if ((recipient.role == Role::decryption && !purposes.first) || (recipient.role == Role::recovery && !purposes.second))
                throw Error("EFS_CERTIFICATE_PURPOSE_MISMATCH");
            if (recipient.wrappedKey.size() != blockSize) throw Error("EFS_INVALID_WRAPPED_KEY");
            std::vector<uint8_t> bigEndian(recipient.wrappedKey.rbegin(), recipient.wrappedKey.rend());
            CFObject<CFDataRef> cipher(CFDataCreate(kCFAllocatorDefault, bigEndian.data(), CFIndex(bigEndian.size())));
            CFErrorRef rawError = nullptr;
            CFObject<CFDataRef> clear(SecKeyCreateDecryptedData(privateKey, kSecKeyAlgorithmRSAEncryptionPKCS1, cipher.get(), &rawError));
            CFObject<CFErrorRef> error(rawError);
            if (!clear.get() || CFDataGetLength(clear.get()) < 16 || CFDataGetLength(clear.get()) > 128) throw Error("EFS_INVALID_WRAPPED_KEY");
            const uint8_t *fek = CFDataGetBytePtr(clear.get());
            const uint32_t declaredKeyLength = little32(fek);
            if (declaredKeyLength > 112 || size_t(CFDataGetLength(clear.get())) != 16 + size_t(declaredKeyLength))
                throw Error("EFS_INVALID_WRAPPED_KEY");
            if (little32(fek + 8) != kAES256) throw Error("EFS_UNSUPPORTED_CONTENT_CIPHER");
            if (CFDataGetLength(clear.get()) != 48 || little32(fek) != 32 || little32(fek + 4) != 256)
                throw Error("EFS_INVALID_FILE_KEY");
            FileKey candidate(SecretBytes(std::vector<uint8_t>(fek + 16, fek + 48)));
            candidate.certificateThumbprint = thumbprint;
            candidate.metadataSHA256 = metadata.sha256;
            candidate.role = recipient.role;
            candidates.push_back(std::move(candidate));
            if (candidates.size() > 1) throw Error("EFS_AMBIGUOUS_KEY_RECIPIENT");
        }
    }
    static FileKey fromPKCS1(const Metadata &metadata, SecretBytes privateDER, const std::vector<uint8_t> &certificateDER) {
        if (privateDER.size() == 0 || privateDER.size() > kPrivateKeyDERLimit || certificateDER.empty() || certificateDER.size() > kCertificateDERLimit)
            throw Error("EFS_KEY_INPUT_LIMIT");
        // Explicit PKCS#1 DER only: no guessed PEM, PKCS#8, PFX or automatic
        // conversion subprocess. Validate canonical integer structure before
        // passing it to the documented nonpersistent SecKeyCreateWithData API.
        try {
            const DERNode top = derNode(privateDER.data(), privateDER.size(), 0);
            if (top.tag != 0x30 || top.end != privateDER.size()) throw Error("EFS_KEY_INPUT_INVALID");
            std::vector<DERNode> integers;
            for (size_t cursor = top.content.start; cursor < top.end;) {
                const DERNode integer = derNode(privateDER.data(), top.end, cursor); cursor = integer.end;
                if (integer.tag != 2) throw Error("EFS_UNSUPPORTED_PRIVATE_KEY_TYPE");
                if (integer.content.length == 0 || privateDER.data()[integer.content.start] & 0x80 ||
                    (integer.content.length > 1 && privateDER.data()[integer.content.start] == 0 &&
                     (privateDER.data()[integer.content.start + 1] & 0x80) == 0)) throw Error("EFS_KEY_INPUT_INVALID");
                integers.push_back(integer);
                if (integers.size() > 9) throw Error("EFS_UNSUPPORTED_PRIVATE_KEY");
            }
            if (integers.size() != 9 || integers[0].content.length != 1 || privateDER.data()[integers[0].content.start] != 0)
                throw Error("EFS_UNSUPPORTED_PRIVATE_KEY");
            Range modulus = integers[1].content;
            if (modulus.length > 1 && privateDER.data()[modulus.start] == 0) { ++modulus.start; --modulus.length; }
            if ((modulus.length != 128 && modulus.length != 256 && modulus.length != 512) || (privateDER.data()[modulus.start] & 0x80) == 0)
                throw Error("EFS_UNSUPPORTED_PRIVATE_KEY");
            for (size_t index = 2; index < integers.size(); ++index)
                if (integers[index].content.length > modulus.length + 1) throw Error("EFS_UNSUPPORTED_PRIVATE_KEY");
            Range exponent = integers[2].content;
            if (exponent.length > 1 && privateDER.data()[exponent.start] == 0) { ++exponent.start; --exponent.length; }
            if (exponent.length > 8) throw Error("EFS_UNSUPPORTED_PRIVATE_KEY");
            uint64_t exponentValue = 0;
            for (size_t index = 0; index < exponent.length; ++index)
                exponentValue = (exponentValue << 8) | privateDER.data()[exponent.start + index];
            if (exponentValue < 3 || (exponentValue & 1) == 0) throw Error("EFS_UNSUPPORTED_PRIVATE_KEY");
        } catch (const Error &error) {
            if (error.code == "EFS_INVALID_CERTIFICATE") throw Error("EFS_KEY_INPUT_INVALID");
            throw;
        }
        CFObject<CFDataRef> privateData(CFDataCreate(kCFAllocatorDefault, privateDER.data(), CFIndex(privateDER.size())));
        CFObject<CFDataRef> certificateData(CFDataCreate(kCFAllocatorDefault, certificateDER.data(), CFIndex(certificateDER.size())));
        CFObject<SecCertificateRef> certificate(SecCertificateCreateWithData(kCFAllocatorDefault, certificateData.get()));
        const void *keys[] = {kSecAttrKeyType, kSecAttrKeyClass};
        const void *values[] = {kSecAttrKeyTypeRSA, kSecAttrKeyClassPrivate};
        CFObject<CFDictionaryRef> attributes(CFDictionaryCreate(kCFAllocatorDefault, keys, values, 2,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
        CFErrorRef rawError = nullptr;
        CFObject<SecKeyRef> key(SecKeyCreateWithData(privateData.get(), attributes.get(), &rawError));
        CFObject<CFErrorRef> error(rawError);
        privateDER.clear(); privateData = CFObject<CFDataRef>();
        if (!key.get() || !certificate.get()) throw Error("EFS_KEY_INPUT_INVALID");
        std::vector<FileKey> candidates;
        collectCandidates(metadata, key.get(), certificate.get(), candidates);
        if (candidates.empty()) throw Error("EFS_NO_MATCHING_PRIVATE_KEY");
        return std::move(candidates.front());
    }

#ifdef NF_EFS_ENABLE_PFX_DIAGNOSTIC
    // Diagnostic-only: Apple PKCS12 import may evaluate certificate trust.
    // Shipping adapters must use fromPKCS1 until trust-fetch isolation is proven.
    static FileKey importAndUnwrapDiagnosticPFX(const Metadata &metadata, SecretBytes pfx, SecretBytes password) {
        if (pfx.size() == 0 || pfx.size() > kPFXLimit || password.size() > kPasswordLimit ||
            (password.size() && std::find(password.data(), password.data() + password.size(), uint8_t(0)) != password.data() + password.size()))
            throw Error("EFS_KEY_INPUT_LIMIT");
        CFObject<CFDataRef> data(CFDataCreate(kCFAllocatorDefault, pfx.data(), CFIndex(pfx.size())));
        CFObject<CFStringRef> passphrase(CFStringCreateWithBytes(kCFAllocatorDefault, password.data(), CFIndex(password.size()), kCFStringEncodingUTF8, false));
        if (!data.get() || !passphrase.get()) throw Error("EFS_KEY_INPUT_INVALID");
        // This explicit flag exists from macOS15. Do not call the default
        // macOS SecPKCS12Import path or create a persistent temporary keychain.
        // SecItemImport(NULL)'s floating PKCS12 private identities are not a
        // reliable fallback, even though its no-persistence option is documented.
        CFArrayRef imported = nullptr;
        OSStatus status = errSecUnimplemented;
        if (__builtin_available(macOS 15.0, *)) {
            const void *keys[] = {kSecImportExportPassphrase, kSecImportToMemoryOnly};
            const void *values[] = {passphrase.get(), kCFBooleanTrue};
            CFObject<CFDictionaryRef> options(CFDictionaryCreate(kCFAllocatorDefault, keys, values, 2,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
            if (!options.get()) throw Error("EFS_KEY_INPUT_INVALID");
            status = SecPKCS12Import(data.get(), options.get(), &imported);
        } else {
            throw Error("EFS_KEY_PLATFORM_UNSUPPORTED");
        }
        CFObject<CFArrayRef> items(imported);
        pfx.clear(); password.clear();
        data = CFObject<CFDataRef>(); passphrase = CFObject<CFStringRef>();
        if (status != errSecSuccess || !items.get()) throw Error("EFS_KEY_IMPORT_FAILED");
        const CFIndex count = CFArrayGetCount(items.get());
        if (count < 1 || count > 64) throw Error("EFS_KEY_IDENTITY_LIMIT");
        std::vector<FileKey> candidates;
        for (CFIndex index = 0; index < count; ++index) {
            CFTypeRef item = CFArrayGetValueAtIndex(items.get(), index);
            if (!item || CFGetTypeID(item) != CFDictionaryGetTypeID()) throw Error("EFS_KEY_IDENTITY_INVALID");
            const CFTypeRef rawIdentity = CFDictionaryGetValue(static_cast<CFDictionaryRef>(item), kSecImportItemIdentity);
            if (!rawIdentity || CFGetTypeID(rawIdentity) != SecIdentityGetTypeID()) continue;
            SecIdentityRef identity = static_cast<SecIdentityRef>(const_cast<void *>(rawIdentity));
            SecCertificateRef certificate = nullptr;
            SecKeyRef privateKey = nullptr;
            const OSStatus certificateStatus = SecIdentityCopyCertificate(identity, &certificate);
            CFObject<SecCertificateRef> ownedCertificate(certificate);
            const OSStatus keyStatus = SecIdentityCopyPrivateKey(identity, &privateKey);
            CFObject<SecKeyRef> ownedKey(privateKey);
            if (certificateStatus != errSecSuccess || keyStatus != errSecSuccess || !certificate || !privateKey)
                throw Error("EFS_KEY_IDENTITY_INVALID");
            collectCandidates(metadata, privateKey, certificate, candidates);
        }
        if (candidates.empty()) throw Error("EFS_NO_MATCHING_PRIVATE_KEY");
        return std::move(candidates.front());
    }

#endif

    void decryptUnit(const std::array<uint8_t, kUnitBytes> &ciphertext, uint64_t logicalByteOffset,
                     std::array<uint8_t, kUnitBytes> &plaintext) const {
        if (logicalByteOffset % kUnitBytes || logicalByteOffset > uint64_t(std::numeric_limits<int64_t>::max()) - kUnitBytes)
            throw Error("EFS_INVALID_CONTENT_GEOMETRY");
        std::array<uint8_t, kCCBlockSizeAES128> iv{};
        storeLittle64(iv.data(), 0x5816657be9161312ULL + logicalByteOffset);
        storeLittle64(iv.data() + 8, 0x1989adbe44918961ULL + logicalByteOffset);
        size_t written = 0;
        const CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0, bytes.data(), bytes.size(), iv.data(),
            ciphertext.data(), ciphertext.size(), plaintext.data(), plaintext.size(), &written);
        if (status != kCCSuccess || written != kUnitBytes) { wipe(plaintext.data(), plaintext.size()); throw Error("EFS_DECRYPT_FAILED"); }
    }
};
} // namespace nativeforensics::efs
