// NativeForensics' process-isolated, read-only Sleuth Kit adapter.
// Original implementation; upstream dependencies have separate notices.
#include <tsk/libtsk.h>
#include <libewf.h>
#include <nlohmann/json.hpp>
#include <CommonCrypto/CommonDigest.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <poll.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#ifndef NF_PATCH_DIGEST
#define NF_PATCH_DIGEST "unverified"
#endif
#ifndef NF_ENGINE_VERSION
#define NF_ENGINE_VERSION "0.1.0-tsk4.15.0"
#endif

namespace {
using Json = nlohmann::json;
constexpr size_t kFrameLimit = 1024 * 1024;
constexpr size_t kResultLimit = 64 * 1024 * 1024;
constexpr size_t kBufferSize = 1024 * 1024;
volatile sig_atomic_t gSignalCancelled = 0;
void cancellationSignal(int) { gSignalCancelled = 1; }

struct Failure : std::runtime_error {
    std::string code;
    Failure(std::string code, std::string message)
        : std::runtime_error(std::move(message)), code(std::move(code)) {}
};
struct Cancelled {};
std::string systemError() { return std::strerror(errno); }
std::string tskError() {
    const char *message = tsk_error_get();
    std::string result = message ? message : "Sleuth Kit operation failed";
    tsk_error_reset();
    return result;
}
bool safeString(const std::string &value) {
    return value.find('\0') == std::string::npos;
}
std::string canonical(const std::string &path) {
    if (path.empty() || path[0] != '/' || !safeString(path))
        throw Failure("INVALID_PATH", "Paths must be absolute local paths without NUL bytes");
    char *resolved = ::realpath(path.c_str(), nullptr);
    if (!resolved) throw Failure("INVALID_PATH", "Cannot resolve path: " + systemError());
    std::string result(resolved);
    std::free(resolved);
    return result;
}

// Read only complete, bounded NDJSON lines. poll() avoids a detached thread that
// might outlive the job's state, and permits cancellation during TSK callbacks.
class Input {
    std::string pending;
    bool ended = false;
    bool cancelled = false;
    std::string jobID;
    bool takeLine(std::string &line) {
        auto newline = pending.find('\n');
        if (newline == std::string::npos) return false;
        if (newline > kFrameLimit) throw Failure("FRAME_TOO_LARGE", "Input frame exceeds 1 MiB");
        line = pending.substr(0, newline);
        pending.erase(0, newline + 1);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        return true;
    }
    void readChunk() {
        std::array<char, 4096> buffer{};
        auto count = ::read(STDIN_FILENO, buffer.data(), buffer.size());
        if (count > 0) {
            pending.append(buffer.data(), size_t(count));
            if (pending.size() > kFrameLimit + buffer.size() && pending.find('\n') == std::string::npos)
                throw Failure("FRAME_TOO_LARGE", "Input frame exceeds 1 MiB");
        } else if (count == 0) ended = true;
        else if (errno != EINTR && errno != EAGAIN)
            throw Failure("INPUT_READ_FAILED", systemError());
    }
public:
    std::string firstLine() {
        std::string line;
        while (!takeLine(line)) {
            if (gSignalCancelled) throw Cancelled{};
            if (ended) throw Failure("TRUNCATED_REQUEST", "Request must end with a newline");
            readChunk();
            if (pending.size() > kFrameLimit && pending.find('\n') == std::string::npos)
                throw Failure("FRAME_TOO_LARGE", "Input frame exceeds 1 MiB");
        }
        return line;
    }
    void setJobID(std::string value) { jobID = std::move(value); }
    void check() {
        if (gSignalCancelled || cancelled) throw Cancelled{};
        std::string line;
        for (;;) {
            while (takeLine(line)) {
                Json message;
                try { message = Json::parse(line); }
                catch (...) { throw Failure("INVALID_CANCEL", "Later input must be a valid cancel message"); }
                if (!message.is_object() || message.value("operation", "") != "cancel" ||
                    message.value("protocolVersion", 0) != 1 ||
                    message.value("jobID", "") != jobID)
                    throw Failure("INVALID_CANCEL", "Later input must cancel this job using protocol v1");
                cancelled = true;
            }
            if (cancelled || gSignalCancelled) throw Cancelled{};
            if (ended) {
                if (!pending.empty()) throw Failure("TRUNCATED_CANCEL", "Cancel frame must end with a newline");
                break;
            }
            pollfd descriptor{STDIN_FILENO, POLLIN, 0};
            int ready = ::poll(&descriptor, 1, 0);
            if (ready < 0 && errno != EINTR) throw Failure("INPUT_READ_FAILED", systemError());
            if (ready <= 0 || !(descriptor.revents & (POLLIN | POLLHUP))) break;
            readChunk();
            if (pending.size() > kFrameLimit && pending.find('\n') == std::string::npos)
                throw Failure("FRAME_TOO_LARGE", "Input frame exceeds 1 MiB");
        }
    }
};

class Output {
    std::string jobID;
    uint64_t sequence = 0;
public:
    size_t bytes = 0;
    explicit Output(std::string value) : jobID(std::move(value)) {}
    void emit(const std::string &type, Json fields = Json::object()) {
        fields["protocolVersion"] = 1;
        fields["jobID"] = jobID;
        fields["sequence"] = sequence;
        fields["type"] = type;
        std::string line = fields.dump(-1, ' ', false, Json::error_handler_t::replace);
        if (line.size() > kFrameLimit) throw Failure("FRAME_TOO_LARGE", "Output frame exceeds 1 MiB");
        line.push_back('\n');
        bool finalFrame = type == "error" || type == "failed" || type == "cancelled" ||
            type == "partial" || type == "completed";
        // Reserve space for a structured error plus terminal even when a large
        // image/progress stream or partition table reaches the response ceiling.
        size_t ceiling = finalFrame ? kResultLimit : kResultLimit - 2 * kFrameLimit;
        if (bytes > ceiling || line.size() > ceiling - bytes)
            throw Failure("RESULT_LIMIT", "Serialized engine responses exceed the 64 MiB ceiling");
        size_t offset = 0;
        while (offset < line.size()) {
            ssize_t count = ::write(STDOUT_FILENO, line.data() + offset, line.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw Failure("OUTPUT_WRITE_FAILED", "Cannot write protocol response");
            offset += size_t(count);
        }
        bytes += line.size();
        ++sequence;
    }
    void progress(std::string stage, int64_t completed, int64_t total, std::string unit) {
        emit("progress", {{"stage", stage}, {"completed", completed}, {"total", total}, {"unit", unit}});
    }
};

struct Snapshot {
    std::string path;
    struct stat status{};
};
bool sameIdentity(const struct stat &left, const struct stat &right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
        left.st_size == right.st_size &&
        left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec &&
        left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec &&
        left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec &&
        left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec;
}
void verifySources(const std::vector<Snapshot> &sources) {
    for (const auto &source : sources) {
        struct stat current{};
        if (::lstat(source.path.c_str(), &current) != 0 || !S_ISREG(current.st_mode) ||
            !sameIdentity(source.status, current))
            throw Failure("SOURCE_CHANGED", "An image segment's identity or metadata changed during the job");
    }
}

int64_t integer(const Json &object, const char *key, int64_t minimum, int64_t maximum) {
    auto iterator = object.find(key);
    if (iterator == object.end() || !iterator->is_number_integer())
        throw Failure("INVALID_REQUEST", std::string(key) + " must be an integer");
    if (iterator->is_number_unsigned() && iterator->get<uint64_t>() > uint64_t(maximum))
        throw Failure("INVALID_REQUEST", std::string(key) + " is out of range");
    int64_t value = iterator->get<int64_t>();
    if (value < minimum || value > maximum)
        throw Failure("INVALID_REQUEST", std::string(key) + " is out of range");
    return value;
}
std::string requiredString(const Json &object, const char *key) {
    auto iterator = object.find(key);
    if (iterator == object.end() || !iterator->is_string())
        throw Failure("INVALID_REQUEST", std::string(key) + " must be a string");
    auto value = iterator->get<std::string>();
    if (value.empty() || !safeString(value))
        throw Failure("INVALID_REQUEST", std::string(key) + " must not be empty or contain NUL bytes");
    return value;
}

struct Request {
    std::string jobID, operation, imageType, timezone;
    uint32_t sectorSize = 0;
    size_t maxFiles = 0;
    bool hashLogicalImage = false;
    std::vector<Snapshot> sources;
    Json file;
    std::string outputPath;
};
Request validate(const Json &json) {
    if (!json.is_object()) throw Failure("INVALID_REQUEST", "Request must be an object");
    integer(json, "protocolVersion", 1, 1);
    Request request;
    request.jobID = requiredString(json, "jobID");
    if (request.jobID.size() > 1024) throw Failure("INVALID_REQUEST", "jobID exceeds 1024 bytes");
    request.operation = requiredString(json, "operation");
    if (request.operation != "inspect" && request.operation != "enumerate" && request.operation != "extract")
        throw Failure("INVALID_REQUEST", "Unknown operation");
    request.imageType = requiredString(json, "imageType");
    if (request.imageType != "auto" && request.imageType != "raw" && request.imageType != "ewf")
        throw Failure("INVALID_REQUEST", "Only auto, raw and ewf image types are supported");
    auto sector = integer(json, "sectorSize", 0, 4096);
    if (sector != 0 && sector != 512 && sector != 4096)
        throw Failure("INVALID_REQUEST", "sectorSize must be 0, 512 or 4096");
    request.sectorSize = uint32_t(sector);
    request.maxFiles = size_t(integer(json, "maxFiles", 1, 50000));
    if (!json.contains("hashLogicalImage") || !json["hashLogicalImage"].is_boolean())
        throw Failure("INVALID_REQUEST", "hashLogicalImage must be a boolean");
    request.hashLogicalImage = json["hashLogicalImage"].get<bool>();
    request.timezone = requiredString(json, "timezone");
    if (request.timezone.size() > 255 || request.timezone.front() == '/' ||
        request.timezone.find("..") != std::string::npos || request.timezone.front() == ':')
        throw Failure("INVALID_TIMEZONE", "timezone must name an installed IANA zone");
    std::string zone = canonical("/usr/share/zoneinfo/" + request.timezone);
    std::string zoneRoot = canonical("/usr/share/zoneinfo");
    struct stat zoneStatus{};
    if (zone.compare(0, zoneRoot.size() + 1, zoneRoot + "/") != 0 ||
        ::stat(zone.c_str(), &zoneStatus) != 0 || !S_ISREG(zoneStatus.st_mode))
        throw Failure("INVALID_TIMEZONE", "timezone must name an installed IANA zone");
    int zoneFD = ::open(zone.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    std::array<char, 4> zoneMagic{};
    ssize_t zoneBytes = zoneFD >= 0 ? ::read(zoneFD, zoneMagic.data(), zoneMagic.size()) : -1;
    if (zoneFD >= 0) ::close(zoneFD);
    if (zoneBytes != 4 || std::memcmp(zoneMagic.data(), "TZif", 4) != 0)
        throw Failure("INVALID_TIMEZONE", "timezone must identify a compiled IANA timezone");
    if (!json.contains("imagePaths") || !json["imagePaths"].is_array() || json["imagePaths"].empty() ||
        json["imagePaths"].size() > 4096)
        throw Failure("INVALID_REQUEST", "imagePaths must contain 1 to 4096 ordered paths");
    std::set<std::pair<dev_t, ino_t>> identities;
    for (const auto &path : json["imagePaths"]) {
        if (!path.is_string()) throw Failure("INVALID_PATH", "imagePaths entries must be strings");
        Snapshot snapshot;
        snapshot.path = canonical(path.get<std::string>());
        int fd = ::open(snapshot.path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) throw Failure("SOURCE_OPEN_FAILED", systemError());
        int result = ::fstat(fd, &snapshot.status);
        ::close(fd);
        if (result != 0 || !S_ISREG(snapshot.status.st_mode) || snapshot.status.st_size <= 0)
            throw Failure("INVALID_SOURCE", "Every image segment must be a nonempty regular file");
        if (!identities.insert({snapshot.status.st_dev, snapshot.status.st_ino}).second)
            throw Failure("DUPLICATE_SEGMENT", "imagePaths contains the same source more than once");
        request.sources.push_back(snapshot);
    }
    if (request.operation == "extract") {
        if (!json.contains("file") || !json["file"].is_object())
            throw Failure("INVALID_REQUEST", "extract requires a file reference");
        request.file = json["file"];
        integer(request.file, "fsOffsetBytes", 0, std::numeric_limits<int64_t>::max());
        auto meta = request.file.find("metaAddress");
        if (meta == request.file.end() || !meta->is_number_integer() ||
            (!meta->is_number_unsigned() && meta->get<int64_t>() < 0))
            throw Failure("INVALID_REQUEST", "metaAddress must be an unsigned integer");
        integer(request.file, "size", 0, std::numeric_limits<int64_t>::max());
        bool hasType = request.file.contains("attributeType") && !request.file["attributeType"].is_null();
        bool hasID = request.file.contains("attributeID") && !request.file["attributeID"].is_null();
        if (hasType != hasID) throw Failure("INVALID_REQUEST", "attributeType and attributeID must be supplied together");
        if (hasType) {
            integer(request.file, "attributeType", 0, 65535);
            integer(request.file, "attributeID", 0, 65535);
        }
        request.outputPath = requiredString(json, "outputPath");
        if (request.outputPath.front() != '/') throw Failure("INVALID_PATH", "outputPath must be absolute");
    }
    return request;
}

bool ewfExtension(const std::string &path) {
    auto extension = std::filesystem::path(path).extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    if (extension.size() == 4 && (extension[1] == 'e' || extension[1] == 'l' || extension[1] == 's'))
        return std::isdigit(static_cast<unsigned char>(extension[2])) && std::isdigit(static_cast<unsigned char>(extension[3]));
    if (extension.size() == 5 && (extension[1] == 'e' || extension[1] == 'l') && extension[2] == 'x')
        return std::isdigit(static_cast<unsigned char>(extension[3])) && std::isdigit(static_cast<unsigned char>(extension[4]));
    return false;
}
using Image = std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)>;
using Filesystem = std::unique_ptr<TSK_FS_INFO, decltype(&tsk_fs_close)>;
using VolumeSystem = std::unique_ptr<TSK_VS_INFO, decltype(&tsk_vs_close)>;
using File = std::unique_ptr<TSK_FS_FILE, decltype(&tsk_fs_file_close)>;

void validateEWFSet(const Request &request) {
    struct Handle {
        libewf_handle_t *value = nullptr;
        bool opened = false;
        ~Handle() {
            libewf_error_t *error = nullptr;
            if (opened) libewf_handle_close(value, &error);
            if (value) libewf_handle_free(&value, &error);
            if (error) libewf_error_free(&error);
        }
    } handle;
    libewf_error_t *error = nullptr;
    auto failed = [&](const std::string &code, const std::string &message) {
        if (error) libewf_error_free(&error);
        throw Failure(code, message);
    };
    if (libewf_handle_initialize(&handle.value, &error) != 1)
        failed("EWF_VALIDATION_FAILED", "Cannot initialize EWF segment validation");
    std::vector<std::string> storage;
    for (const auto &source : request.sources) storage.push_back(source.path);
    std::vector<char *> paths;
    for (auto &path : storage) paths.push_back(path.data());
    // Unlike TSK's single-path convenience wrapper, libewf_handle_open does
    // not glob. This checks only the explicitly identified source segments.
    if (libewf_handle_open(handle.value, paths.data(), int(paths.size()), LIBEWF_OPEN_READ, &error) != 1)
        failed("EWF_OPEN_FAILED", "The explicit EWF segment set could not be opened");
    handle.opened = true;
    int corrupted = libewf_handle_segment_files_corrupted(handle.value, &error);
    if (corrupted != 0)
        failed("EWF_CORRUPTED_OR_INCOMPLETE", "EWF segments are corrupted or incomplete; supply the complete ordered set");
    int encrypted = libewf_handle_segment_files_encrypted(handle.value, &error);
    if (encrypted != 0)
        failed("ENCRYPTED_OR_INVALID_EWF", "Encrypted EWF containers are not supported in Phase 1");
    if (error) libewf_error_free(&error);
}

Image openImage(const Request &request) {
    std::array<unsigned char, 80> header{};
    int fd = ::open(request.sources.front().path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) throw Failure("SOURCE_OPEN_FAILED", systemError());
    auto size = ::read(fd, header.data(), header.size());
    ::close(fd);
    if (size < 0) throw Failure("SOURCE_READ_FAILED", systemError());
    const std::array<unsigned char, 8> ewfV1{{'E', 'V', 'F', 9, 13, 10, 255, 0}};
    const std::array<unsigned char, 8> ewfV2{{'E', 'V', 'F', '2', 13, 10, 129, 0}};
    bool ewfMagic = size >= 8 && (std::memcmp(header.data(), ewfV1.data(), 8) == 0 ||
                                 std::memcmp(header.data(), ewfV2.data(), 8) == 0);
    bool ewfLikeMagic = size >= 3 && std::memcmp(header.data(), "EVF", 3) == 0;
    bool logicalEWF = size >= 8 && (std::memcmp(header.data(), "LVF", 3) == 0 ||
                                   std::memcmp(header.data(), "LEF2", 4) == 0);
    bool namedEWF = ewfExtension(request.sources.front().path);
    if (logicalEWF) throw Failure("UNSUPPORTED_IMAGE", "Logical EWF evidence is not supported in Phase 1");
    if (request.imageType == "raw" && (ewfLikeMagic || namedEWF))
        throw Failure("CONTAINER_AS_RAW", "An EWF container cannot be interpreted as raw disk bytes");
    bool useEWF = request.imageType == "ewf" || (request.imageType == "auto" && (ewfLikeMagic || namedEWF));
    if (useEWF && !ewfMagic)
        throw Failure("INVALID_EWF", "Expected EWF header; refusing raw fallback for a damaged container");
    if (useEWF) {
        // libewf can reorder supplied segments. Check their intrinsic sequence
        // numbers before asking TSK to open the logical image.
        std::array<unsigned char, 16> setID{};
        bool version2 = std::memcmp(header.data(), ewfV2.data(), 8) == 0;
        for (size_t index = 0; index < request.sources.size(); ++index) {
            std::array<unsigned char, 32> segment{};
            int segmentFD = ::open(request.sources[index].path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (segmentFD < 0) throw Failure("SOURCE_OPEN_FAILED", systemError());
            ssize_t bytes = ::read(segmentFD, segment.data(), segment.size());
            ::close(segmentFD);
            if (bytes < (version2 ? 32 : 13) || std::memcmp(segment.data(), version2 ? ewfV2.data() : ewfV1.data(), 8) != 0)
                throw Failure("INVALID_EWF_SEGMENT", "Every segment must have the same supported EWF header version");
            size_t numberOffset = version2 ? 12 : 9;
            uint32_t number = uint32_t(segment[numberOffset]) | (uint32_t(segment[numberOffset + 1]) << 8);
            if (version2) number |= uint32_t(segment[numberOffset + 2]) << 16 | uint32_t(segment[numberOffset + 3]) << 24;
            if (number != index + 1)
                throw Failure("SEGMENT_ORDER_MISMATCH", "Supply EWF segments in contiguous intrinsic sequence order starting at 1");
            if (version2) {
                if (index == 0) std::copy(segment.begin() + 16, segment.end(), setID.begin());
                else if (std::memcmp(segment.data() + 16, setID.data(), setID.size()) != 0)
                    throw Failure("EWF_SET_MISMATCH", "EWF segments belong to different evidence sets");
            }
        }
        validateEWFSet(request);
    }
    if (!useEWF && ((size >= 4 && (std::memcmp(header.data(), "QFI\xfb", 4) == 0 ||
                                  std::memcmp(header.data(), "KDMV", 4) == 0 ||
                                  std::memcmp(header.data(), "AFF", 3) == 0)) ||
                   (size >= 80 && std::memcmp(header.data() + 64, "\x7f\x10\xda\xbe", 4) == 0)))
        throw Failure("UNSUPPORTED_IMAGE", "This image container is outside Phase 1's RAW/EWF capabilities");
    std::vector<const char *> paths;
    for (const auto &source : request.sources) paths.push_back(source.path.c_str());
    tsk_error_reset();
    Image image(tsk_img_open_utf8(int(paths.size()), paths.data(),
        useEWF ? TSK_IMG_TYPE_EWF_EWF : TSK_IMG_TYPE_RAW, request.sectorSize), &tsk_img_close);
    if (!image) throw Failure("IMAGE_OPEN_FAILED", tskError());
    if (image->size <= 0) throw Failure("INVALID_IMAGE_SIZE", "Logical image has no readable bytes");
    // TSK may auto-glob a single E01 or split RAW path. Every source actually
    // used must have been captured by the client and supplied in the request.
    if (image->num_img != int(request.sources.size()))
        throw Failure("UNLISTED_SEGMENTS", "Supply every image segment explicitly in source order");
    for (int index = 0; index < image->num_img; ++index)
        if (!image->images[index] || canonical(image->images[index]) != request.sources[size_t(index)].path)
            throw Failure("SEGMENT_ORDER_MISMATCH", "Engine image segments differ from the ordered request");
    verifySources(request.sources);
    return image;
}

std::string hashFinal(CC_SHA256_CTX &context) {
    std::array<unsigned char, CC_SHA256_DIGEST_LENGTH> digest{};
    CC_SHA256_Final(digest.data(), &context);
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(64);
    for (unsigned char value : digest) { output.push_back(hex[value >> 4]); output.push_back(hex[value & 15]); }
    return output;
}
std::string pathIdentityHash(const std::string &path) {
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    // The TSK directory-walk path is bounded by its recursion limit; chunking
    // also avoids narrowing an arbitrary path length into CommonCrypto's type.
    for (size_t offset = 0; offset < path.size();) {
        size_t amount = std::min(kBufferSize, path.size() - offset);
        CC_SHA256_Update(&context, path.data() + offset, CC_LONG(amount));
        offset += amount;
    }
    return hashFinal(context);
}
std::string logicalHash(TSK_IMG_INFO *image, Input &input, Output &output) {
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    std::vector<char> buffer(kBufferSize);
    int64_t offset = 0, lastProgress = 0;
    int64_t progressStride = std::max<int64_t>(16 * 1024 * 1024, image->size / 4096 + 1);
    output.progress("hashLogicalImage", 0, image->size, "bytes");
    while (offset < image->size) {
        input.check();
        size_t amount = size_t(std::min<int64_t>(buffer.size(), image->size - offset));
        ssize_t count = tsk_img_read(image, offset, buffer.data(), amount);
        if (count <= 0 || size_t(count) > amount) throw Failure("LOGICAL_READ_FAILED", tskError());
        CC_SHA256_Update(&context, buffer.data(), CC_LONG(count));
        offset += count;
        if (offset - lastProgress >= progressStride || offset == image->size) {
            output.progress("hashLogicalImage", offset, image->size, "bytes");
            lastProgress = offset;
        }
    }
    return hashFinal(context);
}

std::string unsupportedFilesystem(TSK_IMG_INFO *image, int64_t offset) {
    std::array<char, 4096> header{};
    auto count = tsk_img_read(image, offset, header.data(), header.size());
    if (count >= 36 && (std::memcmp(header.data() + 32, "NXSB", 4) == 0 ||
                        std::memcmp(header.data() + 32, "APSB", 4) == 0)) return "APFS";
    // UDF's Volume Recognition Sequence begins at sector 16 with 2048-byte
    // sectors, independently of disk-sector size. Reject ISO/UDF bridges too.
    bool began = false, namespaceSeen = false;
    for (int sector = 16; sector < 32; ++sector) {
        if (offset > std::numeric_limits<int64_t>::max() - int64_t(sector) * 2048) break;
        int64_t location = offset + int64_t(sector) * 2048;
        if (location > image->size - 7) break;
        std::array<char, 7> record{};
        if (tsk_img_read(image, location, record.data(), record.size()) != ssize_t(record.size())) break;
        if (record[0] != 0 || record[6] != 1) continue;
        if (std::memcmp(record.data() + 1, "BEA01", 5) == 0) { began = true; namespaceSeen = false; }
        else if (began && (std::memcmp(record.data() + 1, "NSR02", 5) == 0 ||
                           std::memcmp(record.data() + 1, "NSR03", 5) == 0)) namespaceSeen = true;
        else if (began && std::memcmp(record.data() + 1, "TEA01", 5) == 0) {
            if (namespaceSeen) return "UDF";
            began = false;
        }
    }
    tsk_error_reset();
    return "";
}

class Job {
    const Request &request;
    Input &input;
    Output &output;
    Json batch = Json::array();
    size_t batchBytes = 0;
    std::set<std::string> seenIDs;
    bool limitReached = false;
    bool callbackFailed = false;
    std::string callbackError;
public:
    int64_t fileCount = 0;
    int64_t deliveredFileCount = 0;
    int64_t volumeCount = 0;
    bool partial = false;
    Job(const Request &request, Input &input, Output &output) : request(request), input(input), output(output) {}
    void warning(std::string code, std::string message) {
        partial = true;
        output.emit("warning", {{"code", code}, {"message", message}});
    }
    void flush() {
        if (batch.empty()) return;
        output.emit("fileBatch", {{"files", batch}});
        deliveredFileCount += int64_t(batch.size());
        batch = Json::array();
        batchBytes = 0;
    }
    void abandonPending() {
        batch = Json::array();
        batchBytes = 0;
        fileCount = deliveredFileCount;
    }
    bool addEntry(TSK_FS_FILE *file, const char *parentPath, const TSK_FS_ATTR *attribute = nullptr) {
        input.check();
        std::string name = file->name && file->name->name ? file->name->name : "";
        if (name == "." || name == "..") return true;
        std::string path = "/" + std::string(parentPath ? parentPath : "") + name;
        bool directory = file->meta ? TSK_FS_IS_DIR_META(file->meta->type) :
            (file->name && TSK_FS_IS_DIR_NAME(file->name->type));
        if (attribute && attribute->name && attribute->name[0]) {
            name += ":" + std::string(attribute->name);
            path += ":" + std::string(attribute->name);
            directory = false;
        }
        uint64_t address = file->meta ? file->meta->addr : (file->name ? file->name->meta_addr : 0);
        int64_t offset = file->fs_info->offset;
        std::string attrID = attribute ? std::to_string(attribute->type) + "-" + std::to_string(attribute->id) : "default";
        std::string id = std::to_string(offset) + ":" + std::to_string(address) + ":" + attrID + ":" + pathIdentityHash(path);
        if (!seenIDs.insert(id).second) return true;
        if (size_t(fileCount) >= request.maxFiles || output.bytes + batchBytes >= kResultLimit - 2 * kFrameLimit) {
            limitReached = true;
            return false;
        }
        int64_t size = attribute ? attribute->size : (file->meta ? file->meta->size : 0);
        if (size < 0) {
            warning("INVALID_FILE_SIZE", "Skipped a file with negative logical size");
            return true;
        }
        bool deleted = (file->name && (file->name->flags & TSK_FS_NAME_FLAG_UNALLOC)) ||
            (file->meta && (file->meta->flags & TSK_FS_META_FLAG_UNALLOC));
        Json row{{"id", id}, {"path", path}, {"name", name}, {"fsOffsetBytes", offset},
            {"metaAddress", address}, {"size", size}, {"isDirectory", directory}, {"isDeleted", deleted}};
        if (attribute) { row["attributeType"] = int32_t(attribute->type); row["attributeID"] = int32_t(attribute->id); }
        if (file->meta) {
            const auto *meta = file->meta;
            // FAT/exFAT dates start in 1980, so their zero is an absent or
            // invalid timestamp sentinel. Preserve epoch zero on filesystems
            // such as NTFS where it can be a genuine recorded instant.
            const bool fat = TSK_FS_TYPE_ISFAT(file->fs_info->ftype);
            const auto timestamp = [&](const char *epochKey, const char *nanoKey, time_t epoch, uint32_t nano) {
                if (!fat || epoch != 0) {
                    row[epochKey] = int64_t(epoch);
                    row[nanoKey] = int32_t(nano);
                }
            };
            timestamp("createdEpoch", "createdNanoseconds", meta->crtime, meta->crtime_nano);
            timestamp("modifiedEpoch", "modifiedNanoseconds", meta->mtime, meta->mtime_nano);
            timestamp("accessedEpoch", "accessedNanoseconds", meta->atime, meta->atime_nano);
            // FAT/exFAT has no inode-change timestamp; TSK's zero is a missing
            // field here, not recorded evidence that a change occurred in 1970.
            if (!fat) {
                row["changedEpoch"] = int64_t(meta->ctime); row["changedNanoseconds"] = int32_t(meta->ctime_nano);
            }
        } else warning("MISSING_METADATA", "A directory entry lacks metadata; its content cannot be extracted reliably");
        size_t rowBytes;
        try { rowBytes = row.dump().size(); }
        catch (...) {
            warning("INVALID_FILENAME_ENCODING", "Skipped an entry whose filename cannot be represented as valid UTF-8");
            return true;
        }
        if (rowBytes > kFrameLimit - 4096) {
            warning("ENTRY_TOO_LARGE", "Skipped a file entry that exceeds the protocol frame limit");
            return true;
        }
        if (output.bytes + batchBytes + rowBytes + 4096 > kResultLimit - 2 * kFrameLimit) {
            limitReached = true;
            return false;
        }
        if (batch.size() >= 128 || batchBytes + rowBytes > kFrameLimit - 4096) flush();
        batch.push_back(std::move(row));
        batchBytes += rowBytes + 1;
        ++fileCount;
        return true;
    }
    static TSK_WALK_RET_ENUM walkCallback(TSK_FS_FILE *file, const char *path, void *pointer) noexcept {
        auto &job = *static_cast<Job *>(pointer);
        try {
            job.input.check();
            if (!file || !file->fs_info || !file->name) return TSK_WALK_CONT;
            bool emitted = false;
            if (TSK_FS_TYPE_ISNTFS(file->fs_info->ftype) && file->meta) {
                const bool directory = TSK_FS_IS_DIR_META(file->meta->type);
                if (directory) {
                    if (!job.addEntry(file, path)) return TSK_WALK_STOP;
                    emitted = true;
                }
                int attributes = tsk_fs_file_attr_getsize(file);
                if (attributes < 0) { job.warning("ATTRIBUTE_READ_FAILED", tskError()); attributes = 0; }
                for (int index = 0; index < attributes; ++index) {
                    const auto *attribute = tsk_fs_file_attr_get_idx(file, index);
                    if (attribute && attribute->type == TSK_FS_ATTR_TYPE_NTFS_DATA &&
                        (!directory || (attribute->name && attribute->name[0]))) {
                        emitted = true;
                        if (!job.addEntry(file, path, attribute)) return TSK_WALK_STOP;
                    }
                }
            }
            if (!emitted && !job.addEntry(file, path)) return TSK_WALK_STOP;
            return TSK_WALK_CONT;
        } catch (const Cancelled &) { return TSK_WALK_STOP; }
        catch (const std::exception &error) { job.callbackFailed = true; job.callbackError = error.what(); return TSK_WALK_STOP; }
    }
    bool processVolume(TSK_IMG_INFO *image, int64_t offset) {
        input.check();
        Filesystem fs(tsk_fs_open_img(image, offset, TSK_FS_TYPE_DETECT), &tsk_fs_close);
        if (!fs) {
            std::string error = tskError();
            std::string unsupported = unsupportedFilesystem(image, offset);
            if (!unsupported.empty()) warning("UNSUPPORTED_FILESYSTEM", unsupported + " is not supported in Phase 1");
            else warning("FILESYSTEM_OPEN_FAILED", "At byte offset " + std::to_string(offset) + ": " + error);
            return false;
        }
        if (TSK_FS_TYPE_ISAPFS(fs->ftype) || (fs->flags & TSK_FS_INFO_FLAG_ENCRYPTED)) {
            warning("UNSUPPORTED_FILESYSTEM", "APFS and encrypted filesystems are not supported in Phase 1"); return false;
        }
        if (TSK_FS_TYPE_ISISO9660(fs->ftype) && unsupportedFilesystem(image, offset) == "UDF") {
            warning("UNSUPPORTED_FILESYSTEM", "ISO/UDF hybrid filesystems are not supported in Phase 1"); return false;
        }
        if (fs->block_size == 0 || fs->block_count > uint64_t(std::numeric_limits<int64_t>::max())) {
            warning("INVALID_FILESYSTEM_GEOMETRY", "Filesystem geometry exceeds supported bounds"); return false;
        }
        ++volumeCount;
        if (fs->block_count > uint64_t((image->size - offset) / fs->block_size))
            warning("TRUNCATED_FILESYSTEM", "Filesystem's declared size exceeds available logical image bytes");
        if (request.operation == "inspect") return true;
        const char *type = tsk_fs_type_toname(fs->ftype);
        output.emit("volume", {{"volume", {{"id", "fs:" + std::to_string(offset)}, {"offsetBytes", offset},
            {"filesystem", type ? type : "unknown"}, {"blockSize", int64_t(fs->block_size)}, {"blockCount", int64_t(fs->block_count)}}}});
        auto flags = TSK_FS_DIR_WALK_FLAG_ENUM(TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE);
        int result = tsk_fs_dir_walk(fs.get(), fs->root_inum, flags, &Job::walkCallback, this);
        input.check();
        flush();
        if (callbackFailed) throw Failure("ENUMERATION_FAILED", callbackError);
        if (result) warning("DIRECTORY_WALK_FAILED", tskError());
        if (limitReached) warning("RESULT_LIMIT", "Enumeration stopped at the configured file or 64 MiB result limit");
        return true;
    }
    void enumerate(TSK_IMG_INFO *image) {
        VolumeSystem vs(tsk_vs_open(image, 0, TSK_VS_TYPE_DETECT), &tsk_vs_close);
        if (!vs) {
            tsk_error_reset();
            processVolume(image, 0);
        } else {
            if (vs->vstype != TSK_VS_TYPE_DOS && vs->vstype != TSK_VS_TYPE_GPT)
                throw Failure("UNSUPPORTED_VOLUME_SYSTEM", "Only RAW filesystem, MBR and GPT layouts are supported in Phase 1");
            for (TSK_PNUM_T index = 0; index < vs->part_count; ++index) {
                input.check();
                const auto *part = tsk_vs_part_get(vs.get(), index);
                if (!part) { warning("VOLUME_READ_FAILED", tskError()); continue; }
                if (!(part->flags & TSK_VS_PART_FLAG_ALLOC) || (part->flags & TSK_VS_PART_FLAG_META)) continue;
                if (part->desc && std::strstr(part->desc, "Extended")) continue;
                if (vs->block_size == 0 || part->start > uint64_t(std::numeric_limits<int64_t>::max()) / vs->block_size) {
                    warning("INVALID_VOLUME_OFFSET", "Partition offset overflows supported bounds"); continue;
                }
                int64_t offset = int64_t(part->start * vs->block_size);
                if (offset < 0 || offset >= image->size) { warning("INVALID_VOLUME_OFFSET", "Partition begins outside the image"); continue; }
                processVolume(image, offset);
                if (limitReached) break;
            }
        }
        if (volumeCount == 0) throw Failure("NO_SUPPORTED_FILESYSTEM", "No supported readable filesystem was found");
    }
};

// Own a parent directory descriptor so a symlink/rename race cannot redirect
// creation or cleanup. Canonicalization supports macOS' /var and /tmp aliases;
// every component of the resolved parent is then opened without following links.
class NewOutput {
    int parent = -1;
    struct stat created{};
    std::string name;
    std::string requestedPath;
    bool keep = false;
public:
    int fd = -1;
    explicit NewOutput(const std::string &path, const std::vector<Snapshot> &sources) : requestedPath(path) {
        auto parsed = std::filesystem::path(path);
        name = parsed.filename().string();
        if (name.empty() || name == "." || name == "..") throw Failure("INVALID_OUTPUT_PATH", "Invalid output filename");
        std::string resolvedParent = canonical(parsed.parent_path().string());
        std::string target = resolvedParent + "/" + name;
        for (const auto &source : sources)
            if (target == source.path) throw Failure("OUTPUT_IS_SOURCE", "Extraction cannot overwrite an input image");
        parent = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (parent < 0) throw Failure("OUTPUT_OPEN_FAILED", systemError());
        try {
            for (const auto &component : std::filesystem::path(resolvedParent).relative_path()) {
                int next = ::openat(parent, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                if (next < 0) throw Failure("UNSAFE_OUTPUT_PARENT", "Cannot open output parent without following symlinks: " + systemError());
                ::close(parent); parent = next;
            }
            fd = ::openat(parent, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) throw Failure("OUTPUT_EXISTS_OR_UNWRITABLE", "Output must not exist: " + systemError());
            if (::fstat(fd, &created) != 0) throw Failure("OUTPUT_OPEN_FAILED", systemError());
            for (const auto &source : sources)
                if (created.st_dev == source.status.st_dev && created.st_ino == source.status.st_ino)
                    throw Failure("OUTPUT_IS_SOURCE", "Output inode matches an input image");
        } catch (...) { cleanup(); throw; }
    }
    void cleanup() noexcept {
        if (fd >= 0) { ::close(fd); fd = -1; }
        if (parent >= 0) {
            struct stat current{};
            if (!keep && ::fstatat(parent, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) == 0 &&
                current.st_dev == created.st_dev && current.st_ino == created.st_ino)
                ::unlinkat(parent, name.c_str(), 0);
            ::close(parent); parent = -1;
        }
    }
    void finish() {
        if (::fsync(fd) != 0) throw Failure("OUTPUT_SYNC_FAILED", systemError());
        int owned = fd; fd = -1;
        if (::close(owned) != 0) throw Failure("OUTPUT_CLOSE_FAILED", systemError());
        struct stat current{};
        if (::fstatat(parent, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0 ||
            current.st_dev != created.st_dev || current.st_ino != created.st_ino)
            throw Failure("OUTPUT_CHANGED", "Output path changed while extracting");
        struct stat requested{};
        if (::lstat(requestedPath.c_str(), &requested) != 0 ||
            requested.st_dev != created.st_dev || requested.st_ino != created.st_ino)
            throw Failure("OUTPUT_CHANGED", "Requested output path no longer identifies the newly created file");
    }
    void preserve() { keep = true; }
    ~NewOutput() { cleanup(); }
};

// TSK 4.15.0 intentionally returns zero bytes for FILLER runs, while its generic
// attribute reader does not decrypt NTFS EFS attributes. Those compatibility
// behaviors must not become our verified logical-content extraction receipt.
// Sparse runs and the interval after initialized size are different: NTFS
// defines their logical content as zeros, so preserve them without reading
// uninitialized bytes physically stored on disk.
int64_t verifiedReadableBytes(const TSK_FS_ATTR *attribute, TSK_FS_INFO *fs, Input &input) {
    if (!TSK_FS_TYPE_ISNTFS(fs->ftype)) return attribute->size;
    if (attribute->flags & TSK_FS_ATTR_ENC)
        throw Failure("UNSUPPORTED_ENCRYPTED_CONTENT", "NTFS encrypted attribute content cannot be decrypted by this engine");
    // Compressed readers consume whole compression units, including mappings
    // beyond the requested initialized prefix. Their complete-byte semantics
    // require an independent compression corpus before being advertised here.
    if (attribute->flags & TSK_FS_ATTR_COMP)
        throw Failure("UNSUPPORTED_COMPRESSED_CONTENT", "NTFS compressed attribute extraction is not validated by this engine");
    if (!(attribute->flags & TSK_FS_ATTR_NONRES)) return attribute->size;
    if (fs->block_size == 0 || attribute->nrd.initsize < 0 || attribute->nrd.initsize > attribute->size ||
        attribute->nrd.skiplen != 0)
        throw Failure("INCOMPLETE_ATTRIBUTE_RUNLIST", "NTFS attribute has invalid initialized-content geometry");
    const uint64_t initialized = uint64_t(attribute->nrd.initsize);
    const uint64_t requiredBlocks = initialized / fs->block_size + (initialized % fs->block_size != 0);
    uint64_t covered = 0;
    std::set<const TSK_FS_ATTR_RUN *> seen;
    for (const auto *run = attribute->nrd.run; covered < requiredBlocks && run; run = run->next) {
        input.check();
        if (!seen.insert(run).second || run->len == 0 || run->offset != covered ||
            (run->flags & TSK_FS_ATTR_RUN_FLAG_FILLER))
            throw Failure("INCOMPLETE_ATTRIBUTE_RUNLIST", "NTFS initialized content has missing, overlapping, or filler data runs");
        if (run->flags & TSK_FS_ATTR_RUN_FLAG_ENCRYPTED)
            throw Failure("UNSUPPORTED_ENCRYPTED_CONTENT", "NTFS encrypted data runs cannot be decrypted by this engine");
        // Clamp rather than multiply untrusted lengths or overflow a VCN sum.
        covered += std::min<uint64_t>(run->len, requiredBlocks - covered);
    }
    if (covered != requiredBlocks)
        throw Failure("INCOMPLETE_ATTRIBUTE_RUNLIST", "NTFS data runs do not cover all initialized logical content");
    return attribute->nrd.initsize;
}

void extract(const Request &request, TSK_IMG_INFO *image, Input &input, Output &output) {
    int64_t offset = request.file["fsOffsetBytes"].get<int64_t>();
    if (offset >= image->size) throw Failure("INVALID_FILE_REFERENCE", "Filesystem offset is outside the logical image");
    Filesystem fs(tsk_fs_open_img(image, offset, TSK_FS_TYPE_DETECT), &tsk_fs_close);
    if (!fs) {
        std::string error = tskError();
        auto unsupported = unsupportedFilesystem(image, offset);
        if (!unsupported.empty()) throw Failure("UNSUPPORTED_FILESYSTEM", unsupported + " is not supported in Phase 1");
        throw Failure("FILESYSTEM_OPEN_FAILED", error);
    }
    if (TSK_FS_TYPE_ISAPFS(fs->ftype) || (fs->flags & TSK_FS_INFO_FLAG_ENCRYPTED))
        throw Failure("UNSUPPORTED_FILESYSTEM", "APFS and encrypted filesystems are not supported in Phase 1");
    if (TSK_FS_TYPE_ISISO9660(fs->ftype) && unsupportedFilesystem(image, offset) == "UDF")
        throw Failure("UNSUPPORTED_FILESYSTEM", "ISO/UDF hybrid filesystems are not supported in Phase 1");
    uint64_t metaAddress = request.file["metaAddress"].get<uint64_t>();
    if (metaAddress < fs->first_inum || metaAddress > fs->last_inum)
        throw Failure("INVALID_FILE_REFERENCE", "Metadata address is outside the filesystem");
    File file(tsk_fs_file_open_meta(fs.get(), nullptr, metaAddress), &tsk_fs_file_close);
    if (!file || !file->meta) throw Failure("FILE_OPEN_FAILED", tskError());
    bool hasAttribute = request.file.contains("attributeType") && !request.file["attributeType"].is_null();
    const TSK_FS_ATTR *attribute = hasAttribute ?
        tsk_fs_file_attr_get_type(file.get(), TSK_FS_ATTR_TYPE_ENUM(request.file["attributeType"].get<int32_t>()),
            uint16_t(request.file["attributeID"].get<int32_t>()), 1) : tsk_fs_file_attr_get(file.get());
    if (!attribute) throw Failure("ATTRIBUTE_OPEN_FAILED", tskError());
    bool namedStream = hasAttribute && attribute->name && attribute->name[0];
    if (TSK_FS_IS_DIR_META(file->meta->type) && !namedStream)
        throw Failure("DIRECTORY_EXTRACTION", "Select a file or named data stream to extract");
    int64_t expected = request.file["size"].get<int64_t>();
    if (attribute->size != expected) throw Failure("FILE_SIZE_MISMATCH", "Current file size differs from the enumerated reference");
    const int64_t readableBytes = verifiedReadableBytes(attribute, fs.get(), input);
    NewOutput destination(request.outputPath, request.sources);
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    std::vector<char> buffer(kBufferSize);
    int64_t position = 0, lastProgress = 0;
    int64_t progressStride = std::max<int64_t>(16 * 1024 * 1024, expected / 4096 + 1);
    output.progress("extract", 0, expected, "bytes");
    while (position < expected) {
        input.check();
        size_t amount = size_t(std::min<int64_t>(buffer.size(), expected - position));
        // TSK 4.15 automatically attempts deleted FAT recovery while loading its
        // run list. A separate legacy icat -r flag no longer exists in the API.
        ssize_t count;
        if (position >= readableBytes) {
            std::fill_n(buffer.data(), amount, 0);
            count = ssize_t(amount);
        } else {
            amount = size_t(std::min<int64_t>(amount, readableBytes - position));
            count = tsk_fs_attr_read(attribute, position, buffer.data(), amount, TSK_FS_FILE_READ_FLAG_NONE);
        }
        if (count <= 0 || size_t(count) > amount) throw Failure("FILE_READ_FAILED", tskError());
        size_t written = 0;
        while (written < size_t(count)) {
            input.check();
            ssize_t result = ::write(destination.fd, buffer.data() + written, size_t(count) - written);
            if (result < 0 && errno == EINTR) continue;
            if (result <= 0) throw Failure("OUTPUT_WRITE_FAILED", systemError());
            written += size_t(result);
        }
        CC_SHA256_Update(&context, buffer.data(), CC_LONG(count));
        position += count;
        if (position - lastProgress >= progressStride || position == expected) {
            output.progress("extract", position, expected, "bytes");
            lastProgress = position;
        }
    }
    input.check();
    verifySources(request.sources);
    destination.finish();
    std::string digest = hashFinal(context);
    output.emit("extracted", {{"outputPath", request.outputPath}, {"byteCount", position}, {"sha256", digest}});
    input.check();
    output.emit("completed", {{"fileCount", 0}});
    destination.preserve();
}
} // namespace

int main() {
    struct sigaction action{};
    action.sa_handler = cancellationSignal;
    sigemptyset(&action.sa_mask);
    // No SA_RESTART: a signal must wake a blocked initial stdin read as well as
    // setting the cancellation flag used by native parsing/hash callbacks.
    ::sigaction(SIGTERM, &action, nullptr);
    ::sigaction(SIGINT, &action, nullptr);
    ::signal(SIGPIPE, SIG_IGN);
    tsk_verbose = 0;
    Input input;
    std::unique_ptr<Output> output;
    std::unique_ptr<Job> job;
    try {
        Json json;
        try { json = Json::parse(input.firstLine()); }
        catch (const Json::exception &) { throw Failure("INVALID_JSON", "Request is not valid UTF-8 JSON"); }
        std::string jobID = json.is_object() && json.contains("jobID") && json["jobID"].is_string() ? json["jobID"].get<std::string>() : "";
        if (jobID.size() > 1024) jobID.clear();
        output = std::make_unique<Output>(jobID);
        output->emit("hello", {{"engineVersion", NF_ENGINE_VERSION}, {"patchDigest", NF_PATCH_DIGEST},
            {"capabilities", {"raw", "ewf", "mbr", "gpt", "filesystem-enumeration", "deleted-file-entries", "ntfs-data-streams", "logical-image-sha256", "file-extraction-sha256"}}});
        Request request = validate(json);
        input.setJobID(request.jobID);
        input.check();
        if (::setenv("TZ", request.timezone.c_str(), 1) != 0) throw Failure("TIMEZONE_FAILED", systemError());
        ::tzset();
        Image image = openImage(request);
        Json imageResponse{{"imageType", TSK_IMG_TYPE_ISEWF(image->itype) ? "ewf" : "raw"},
            {"logicalSize", int64_t(image->size)}, {"sectorSize", int(image->sector_size)}};
        imageResponse["imagePaths"] = Json::array();
        // openImage verified these canonical paths against every path TSK
        // actually opened, in the same intrinsic/source order.
        for (const auto &source : request.sources) imageResponse["imagePaths"].push_back(source.path);
        if (request.hashLogicalImage) imageResponse["logicalSha256"] = logicalHash(image.get(), input, *output);
        output->emit("image", std::move(imageResponse));
        input.check();
        if (request.operation == "extract") extract(request, image.get(), input, *output);
        else {
            job = std::make_unique<Job>(request, input, *output);
            job->enumerate(image.get());
            input.check();
            verifySources(request.sources);
            output->emit(job->partial ? "partial" : "completed", {{"fileCount", job->fileCount}});
        }
        return 0;
    } catch (const Cancelled &) {
        try {
            if (!output) output = std::make_unique<Output>("");
            if (job) { try { job->flush(); } catch (...) { job->abandonPending(); } }
            output->emit("cancelled", {{"fileCount", job ? job->fileCount : 0}});
        } catch (...) {}
        return 2;
    } catch (const Failure &failure) {
        try {
            if (!output) output = std::make_unique<Output>("");
            if (job) { try { job->flush(); } catch (...) { job->abandonPending(); } }
            output->emit("error", {{"code", failure.code}, {"message", failure.what()}});
            output->emit("failed", {{"fileCount", job ? job->fileCount : 0}});
        } catch (...) {}
        return 1;
    } catch (const std::exception &failure) {
        try {
            if (!output) output = std::make_unique<Output>("");
            if (job) { try { job->flush(); } catch (...) { job->abandonPending(); } }
            output->emit("error", {{"code", "INTERNAL_ERROR"}, {"message", failure.what()}});
            output->emit("failed", {{"fileCount", job ? job->fileCount : 0}});
        } catch (...) {}
        return 1;
    }
}
