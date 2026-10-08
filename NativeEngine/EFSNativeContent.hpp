// Original bounded TSK metadata/mapping adapter for the validated EFS profile.
// No TSK flags, filesystem metadata or image bytes are changed.
#pragma once
#include "EFSKeyPipeline.hpp"
#include <tsk/libtsk.h>
#include <set>

namespace nativeforensics::efs {
constexpr size_t kMappingRunLimit = 65536;
// TSK classifies some NTFS reparse records as REG. Do not use that enum alone
// to advertise or admit the regular-file EFS profile. Standard Information's
// file attributes are a LE32 at32; FILE_ATTRIBUTE_REPARSE_POINT is0x400.
template <typename Check> bool eligibleRegularRecord(TSK_FS_FILE *file, Check check) {
    if (!file || !file->meta || file->meta->type != TSK_FS_META_TYPE_REG ||
        (file->meta->flags & TSK_FS_META_FLAG_UNALLOC)) return false;
    const int count = tsk_fs_file_attr_getsize(file);
    if (count <= 0 || count > 1024) return false;
    bool informationSeen = false;
    for (int index = 0; index < count; ++index) {
        check();
        const TSK_FS_ATTR *attribute = tsk_fs_file_attr_get_idx(file, index);
        if (!attribute || attribute->type == TSK_FS_ATTR_TYPE_NTFS_REPARSE) return false;
        if (attribute->type != TSK_FS_ATTR_TYPE_NTFS_SI) continue;
        if (informationSeen || attribute->size < 36 || !(attribute->flags & TSK_FS_ATTR_RES) ||
            (attribute->flags & (TSK_FS_ATTR_ENC | TSK_FS_ATTR_COMP | TSK_FS_ATTR_SPARSE))) return false;
        informationSeen = true;
        std::array<uint8_t, 4> fileAttributes{};
        if (tsk_fs_attr_read(attribute, 32, reinterpret_cast<char *>(fileAttributes.data()), fileAttributes.size(), TSK_FS_FILE_READ_FLAG_NONE) != 4) {
            tsk_error_reset(); return false;
        }
        if (little32(fileAttributes.data()) & 0x400) return false;
    }
    return informationSeen;
}
class NativeContent {
    struct Run { uint64_t first, count, physical; };
    TSK_FS_INFO *fs;
    FileKey key;
    std::vector<Run> runs;
    uint64_t size = 0, ciphertextSize = 0, nextPosition = 0;
    uint64_t cachedUnit = std::numeric_limits<uint64_t>::max();
    std::array<uint8_t, kUnitBytes> cachedPlaintext{};
    CC_SHA256_CTX cipherHash{};
    uint64_t cipherBytesHashed = 0;

    template <typename Check> static std::vector<uint8_t> metadataBytes(TSK_FS_FILE *file, Check check) {
        if (!file || !file->meta || !TSK_FS_TYPE_ISNTFS(file->fs_info->ftype))
            throw Error("EFS_UNSUPPORTED_FILESYSTEM");
        const int count = tsk_fs_file_attr_getsize(file);
        if (count <= 0 || count > 1024) throw Error("EFS_METADATA_ATTRIBUTE_LIMIT");
        const TSK_FS_ATTR *metadata = nullptr;
        for (int index = 0; index < count; ++index) {
            check();
            const TSK_FS_ATTR *attribute = tsk_fs_file_attr_get_idx(file, index);
            if (!attribute) throw Error("EFS_METADATA_READ_FAILED");
            if (attribute->type == TSK_FS_ATTR_TYPE_NTFS_LOG && attribute->name && std::strcmp(attribute->name, "$EFS") == 0) {
                if (metadata) throw Error("EFS_AMBIGUOUS_METADATA");
                metadata = attribute;
            }
        }
        if (!metadata) throw Error("EFS_METADATA_MISSING");
        if (metadata->size < 0 || metadata->size > int64_t(kMetadataLimit) ||
            (metadata->flags & (TSK_FS_ATTR_ENC | TSK_FS_ATTR_COMP | TSK_FS_ATTR_SPARSE)))
            throw Error("EFS_UNSUPPORTED_METADATA_PROFILE");
        if (metadata->flags & TSK_FS_ATTR_NONRES) {
            if (metadata->nrd.initsize != metadata->size || metadata->nrd.skiplen != 0)
                throw Error("EFS_INCOMPLETE_METADATA_MAPPING");
            validateRuns(metadata, file->fs_info, uint64_t(metadata->size), check);
        } else if (!(metadata->flags & TSK_FS_ATTR_RES)) {
            throw Error("EFS_UNSUPPORTED_METADATA_PROFILE");
        }
        std::vector<uint8_t> bytes(size_t(metadata->size));
        check();
        const ssize_t received = tsk_fs_attr_read(metadata, 0, reinterpret_cast<char *>(bytes.data()), bytes.size(), TSK_FS_FILE_READ_FLAG_NONE);
        if (received != ssize_t(bytes.size())) throw Error("EFS_METADATA_READ_FAILED");
        check();
        return bytes;
    }
    template <typename Check> static std::vector<Run> validateRuns(const TSK_FS_ATTR *attribute, TSK_FS_INFO *fs, uint64_t neededBytes, Check check) {
        if (!fs->block_size || fs->block_size > 65536 || fs->block_size % kUnitBytes ||
            attribute->nrd.skiplen != 0 || attribute->nrd.allocsize < 0 || uint64_t(attribute->nrd.allocsize) < neededBytes)
            throw Error("EFS_INVALID_CONTENT_GEOMETRY");
        const uint64_t neededBlocks = neededBytes / fs->block_size + (neededBytes % fs->block_size != 0);
        uint64_t covered = 0;
        std::set<const TSK_FS_ATTR_RUN *> seen;
        std::vector<Run> result;
        for (const auto *run = attribute->nrd.run; run && covered < neededBlocks; run = run->next) {
            check();
            if (result.size() >= kMappingRunLimit) throw Error("EFS_MAPPING_LIMIT");
            if (!seen.insert(run).second || run->offset != covered || run->len == 0 ||
                (run->flags & (TSK_FS_ATTR_RUN_FLAG_FILLER | TSK_FS_ATTR_RUN_FLAG_SPARSE)) ||
                run->addr == 0 || run->addr > fs->last_block_act || run->len - 1 > fs->last_block_act - run->addr)
                throw Error("EFS_INCOMPLETE_CONTENT_MAPPING");
            const uint64_t count = std::min<uint64_t>(run->len, neededBlocks - covered);
            result.push_back({covered, count, run->addr});
            covered += count;
        }
        if (covered != neededBlocks) throw Error("EFS_INCOMPLETE_CONTENT_MAPPING");
        return result;
    }
    template <typename Check> static FileKey prepareKey(TSK_FS_FILE *file, const TSK_FS_ATTR *attribute,
        SecretBytes privateDER, const std::vector<uint8_t> &certificateDER, Check check) {
        if (!file || !file->meta || !TSK_FS_TYPE_ISNTFS(file->fs_info->ftype))
            throw Error("EFS_UNSUPPORTED_FILESYSTEM");
        if (!eligibleRegularRecord(file, check)) throw Error("EFS_UNSUPPORTED_FILE_PROFILE");
        if (!attribute || attribute->type != TSK_FS_ATTR_TYPE_NTFS_DATA ||
            (attribute->name && attribute->name[0]) || !(attribute->flags & TSK_FS_ATTR_NONRES) ||
            !(attribute->flags & TSK_FS_ATTR_ENC) || (attribute->flags & (TSK_FS_ATTR_COMP | TSK_FS_ATTR_SPARSE)))
            throw Error("EFS_UNSUPPORTED_FILE_PROFILE");
        if (attribute->size < 0 || attribute->nrd.initsize != attribute->size)
            throw Error("EFS_UNSUPPORTED_INITIALIZED_TAIL");
        check();
        const Metadata metadata = parseMetadata(metadataBytes(file, check));
        auto key = FileKey::fromPKCS1(metadata, std::move(privateDER), certificateDER);
        check();
        return key;
    }
    template <typename Check> void loadUnit(uint64_t unit, Check check) {
        check();
        const uint64_t byteOffset = unit * kUnitBytes, block = byteOffset / fs->block_size, within = byteOffset % fs->block_size;
        const auto found = std::upper_bound(runs.begin(), runs.end(), block,
            [](uint64_t value, const Run &run) { return value < run.first; });
        if (found == runs.begin()) throw Error("EFS_INCOMPLETE_CONTENT_MAPPING");
        const Run &run = *std::prev(found);
        if (block - run.first >= run.count || within > fs->block_size - kUnitBytes)
            throw Error("EFS_INCOMPLETE_CONTENT_MAPPING");
        const uint64_t physicalBlock = run.physical + block - run.first;
        if (physicalBlock > uint64_t(std::numeric_limits<int64_t>::max()) / fs->block_size ||
            physicalBlock * fs->block_size > uint64_t(std::numeric_limits<int64_t>::max()) - within)
            throw Error("EFS_INVALID_CONTENT_GEOMETRY");
        std::array<uint8_t, kUnitBytes> ciphertext{};
        const ssize_t received = tsk_fs_read(fs, int64_t(physicalBlock * fs->block_size + within),
            reinterpret_cast<char *>(ciphertext.data()), ciphertext.size());
        if (received != ssize_t(ciphertext.size())) throw Error("EFS_CONTENT_READ_FAILED");
        check();
        wipe(cachedPlaintext.data(), cachedPlaintext.size());
        key.decryptUnit(ciphertext, byteOffset, cachedPlaintext);
        CC_SHA256_Update(&cipherHash, ciphertext.data(), CC_LONG(ciphertext.size()));
        cipherBytesHashed += ciphertext.size();
        cachedUnit = unit;
    }
public:
    template <typename Check> NativeContent(TSK_FS_FILE *file, const TSK_FS_ATTR *attribute,
        SecretBytes privateDER, const std::vector<uint8_t> &certificateDER, Check check)
        : fs(file ? file->fs_info : nullptr), key(prepareKey(file, attribute, std::move(privateDER), certificateDER, check)) {
        size = uint64_t(attribute->size);
        if (size > uint64_t(std::numeric_limits<int64_t>::max()) - (kUnitBytes - 1))
            throw Error("EFS_INVALID_CONTENT_GEOMETRY");
        ciphertextSize = size + (kUnitBytes - size % kUnitBytes) % kUnitBytes;
        runs = validateRuns(attribute, fs, ciphertextSize, check);
        CC_SHA256_Init(&cipherHash);
    }
    NativeContent(const NativeContent &) = delete;
    NativeContent &operator=(const NativeContent &) = delete;
    ~NativeContent() { wipe(cachedPlaintext.data(), cachedPlaintext.size()); }
    template <typename Check> ssize_t read(int64_t position, char *output, size_t amount, Check check) {
        if (position < 0 || uint64_t(position) != nextPosition || uint64_t(position) > size || amount > size - uint64_t(position))
            throw Error("EFS_INVALID_READ_POSITION");
        size_t copied = 0;
        while (copied < amount) {
            check();
            const uint64_t current = uint64_t(position) + copied, unit = current / kUnitBytes;
            if (cachedUnit != unit) loadUnit(unit, check);
            const size_t within = size_t(current % kUnitBytes), count = std::min<size_t>(amount - copied, kUnitBytes - within);
            std::memcpy(output + copied, cachedPlaintext.data() + within, count);
            copied += count;
        }
        nextPosition += copied;
        return ssize_t(copied);
    }
    std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> ciphertextSHA256() const {
        if (nextPosition != size || cipherBytesHashed != ciphertextSize) throw Error("EFS_INCOMPLETE_EXPORT");
        auto context = cipherHash;
        std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> digest{};
        CC_SHA256_Final(digest.data(), &context);
        return digest;
    }
    const FileKey &provenance() const { return key; }
    uint64_t physicalCiphertextBytes() const { return ciphertextSize; }
};
} // namespace nativeforensics::efs
