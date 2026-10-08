// Read-only TSK metadata inspection for the approved public EFS corpus.
// No keys, decryption, mounting, metadata repair or source writes.
#include <tsk/libtsk.h>
#include <nlohmann/json.hpp>
#include <CommonCrypto/CommonDigest.h>
#include <cstring>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
using Json = nlohmann::json;
std::string sha(const std::vector<char> &bytes) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(bytes.data(), CC_LONG(bytes.size()), digest);
    std::string result;
    constexpr char hex[] = "0123456789abcdef";
    for (unsigned char value : digest) { result.push_back(hex[value >> 4]); result.push_back(hex[value & 15]); }
    return result;
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    try {
        const char *path[] = {argv[1]};
        std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> image(tsk_img_open_utf8(1, path, TSK_IMG_TYPE_DETECT, 0), &tsk_img_close);
        if (!image) return 3;
        std::unique_ptr<TSK_FS_INFO, decltype(&tsk_fs_close)> fs(tsk_fs_open_img(image.get(), 0, TSK_FS_TYPE_DETECT), &tsk_fs_close);
        if (!fs || !TSK_FS_TYPE_ISNTFS(fs->ftype)) return 4;
        const uint64_t inode = std::stoull(argv[2]);
        std::unique_ptr<TSK_FS_FILE, decltype(&tsk_fs_file_close)> file(tsk_fs_file_open_meta(fs.get(), nullptr, inode), &tsk_fs_file_close);
        if (!file || !file->meta) return 5;
        Json result{{"schemaVersion", 1}, {"logicalImageBytes", image->size}, {"fsBlockSize", fs->block_size},
                    {"fileMetaType", int(file->meta->type)}, {"fileMetaFlags", int(file->meta->flags)}, {"attributes", Json::array()}};
        const int count = tsk_fs_file_attr_getsize(file.get());
        if (count < 0 || count > 1024) return 6;
        for (int index = 0; index < count; ++index) {
            const auto *attribute = tsk_fs_file_attr_get_idx(file.get(), index);
            if (!attribute) return 7;
            Json row{{"type", int(attribute->type)}, {"id", attribute->id}, {"size", attribute->size},
                     {"name", attribute->name ? attribute->name : ""}, {"flags", int(attribute->flags)}};
            if (attribute->flags & TSK_FS_ATTR_NONRES) {
                row["initializedBytes"] = attribute->nrd.initsize;
                row["allocatedBytes"] = attribute->nrd.allocsize;
                row["runs"] = Json::array();
                size_t seen = 0;
                for (auto *run = attribute->nrd.run; run; run = run->next) {
                    if (++seen > 65536) return 8;
                    row["runs"].push_back({{"first", run->offset}, {"address", run->addr}, {"blocks", run->len}, {"flags", int(run->flags)}});
                }
            }
            if (attribute->type == TSK_FS_ATTR_TYPE_NTFS_LOG && attribute->name &&
                std::strcmp(attribute->name, "$EFS") == 0 && attribute->size > 0 && attribute->size <= 262144) {
                std::vector<char> metadata(size_t(attribute->size));
                if (tsk_fs_attr_read(attribute, 0, metadata.data(), metadata.size(), TSK_FS_FILE_READ_FLAG_NONE) != ssize_t(metadata.size())) return 9;
                const int fd = ::open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
                if (fd < 0) return 10;
                size_t written = 0;
                while (written < metadata.size()) {
                    const ssize_t count = ::write(fd, metadata.data() + written, metadata.size() - written);
                    if (count < 0 && errno == EINTR) continue;
                    if (count <= 0) { ::close(fd); return 11; }
                    written += size_t(count);
                }
                if (::fsync(fd) != 0) { ::close(fd); return 11; }
                if (::close(fd) != 0) return 11;
                row["metadataSHA256"] = sha(metadata);
                row["metadataBytes"] = metadata.size();
            }
            result["attributes"].push_back(std::move(row));
        }
        std::cout << result.dump() << '\n';
        return 0;
    } catch (...) { return 12; }
}
