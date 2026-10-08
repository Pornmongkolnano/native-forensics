// Synthetic parser-worker fixture only. Never package this as the shipping worker.
// Replace only an owned test app copy's worker; retain its shipping broker/client.
// Paths/port are compile-time constants for resources owned by the test harness.
#import <Foundation/Foundation.h>
#import <Security/SecTask.h>
#import "NFDecoderIPC.h"
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <poll.h>
#include <pthread.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef NF_XPC_CANARY_PATH
#error "Compile with a fixed path to an owned synthetic outside-container canary."
#endif
#ifndef NF_XPC_LOOPBACK_PORT
#error "Compile with the ephemeral port of the harness-owned loopback listener."
#endif
#ifndef NF_XPC_INHERITED_CONTROL_DIRECTORY
#error "Compile with a fixed owned private control directory in the inherited broker container."
#endif
#ifndef NF_TEST_HELLO_DELAY_MS
#define NF_TEST_HELLO_DELAY_MS 0
#endif
#ifndef NF_TEST_BAD_HELLO_VERSION
#define NF_TEST_BAD_HELLO_VERSION 0
#endif
#if NF_TEST_HELLO_DELAY_MS < 0 || NF_TEST_HELLO_DELAY_MS > 2000
#error "The synthetic hello delay must be bounded to 0...2000 ms."
#endif

static const NSUInteger NFInputLimit = 128 * 1024 * 1024;
static const NSUInteger NFControlLimit = 4096;
static const NSUInteger NFResponseLimit = 2 * 1024 * 1024;
static atomic_uint_fast64_t NFDeadlineNanoseconds;
static atomic_bool NFBodyComplete;

static uint64_t NFUptimeNanoseconds(void) {
    static mach_timebase_info_data_t scale;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ mach_timebase_info(&scale); });
    if (!scale.denom) _exit(78);
    return (uint64_t)(((__uint128_t)mach_absolute_time() * scale.numer) / scale.denom);
}

// This thread neither parses input nor depends on the parser returning. The
// broker must keep its stdin writer open while the worker owns this request.
static void *NFWatchdogMain(void *unused) {
    (void)unused;
    for (;;) {
        uint64_t now = NFUptimeNanoseconds();
        uint64_t deadline = atomic_load_explicit(&NFDeadlineNanoseconds, memory_order_acquire);
        if (now >= deadline) _exit(0);
        uint64_t remainingMilliseconds = (deadline - now + NSEC_PER_MSEC - 1) / NSEC_PER_MSEC;
        int waitMilliseconds = (int)(remainingMilliseconds > 25 ? 25 : remainingMilliseconds);
        if (waitMilliseconds < 1) waitMilliseconds = 1;
        if (atomic_load_explicit(&NFBodyComplete, memory_order_acquire)) {
            struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN | POLLHUP | POLLERR};
            int status = poll(&input, 1, waitMilliseconds);
            if (status < 0) {
                if (errno == EINTR) continue;
                _exit(74);
            }
            // No message is permitted after the exact declared body. HUP/ERR
            // retires cancelled work; POLLIN rejects an extra request/body byte.
            if (status > 0 && (input.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) _exit(0);
        } else {
            struct timespec delay = {.tv_sec = 0, .tv_nsec = (long)waitMilliseconds * NSEC_PER_MSEC};
            while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
        }
    }
    return NULL;
}

static BOOL NFReadExact(int descriptor, void *buffer, size_t length) {
    unsigned char *cursor = buffer;
    while (length) {
        ssize_t count = read(descriptor, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return NO;
        cursor += count;
        length -= (size_t)count;
    }
    return YES;
}

static NSData *NFReadFrame(NSUInteger limit) {
    uint32_t networkLength = 0;
    if (!NFReadExact(STDIN_FILENO, &networkLength, sizeof(networkLength))) return nil;
    uint32_t length = ntohl(networkLength);
    if (!length || length > limit) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:length];
    return NFReadExact(STDIN_FILENO, data.mutableBytes, length) ? data : nil;
}

static BOOL NFInputIdleAndOpen(void) {
    struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN | POLLHUP | POLLERR};
    int status;
    do { status = poll(&input, 1, 0); } while (status < 0 && errno == EINTR);
    return status == 0;
}

static BOOL NFWriteExact(int descriptor, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;
    while (length) {
        size_t requested = length > 64 * 1024 ? 64 * 1024 : length;
        ssize_t count = write(descriptor, cursor, requested);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return NO;
        cursor += count;
        length -= (size_t)count;
    }
    return YES;
}

static BOOL NFWriteFrame(NSData *data, NSUInteger limit) {
    if (!data.length || data.length > limit || data.length > UINT32_MAX) return NO;
    uint32_t networkLength = htonl((uint32_t)data.length);
    return NFWriteExact(STDOUT_FILENO, &networkLength, sizeof(networkLength)) &&
        NFWriteExact(STDOUT_FILENO, data.bytes, data.length);
}

static BOOL NFHex(NSString *value, NSUInteger size) {
    if (![value isKindOfClass:NSString.class] || [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] != size) return NO;
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    const unsigned char *bytes = data.bytes;
    for (NSUInteger i = 0; i < data.length; ++i) {
        if (!((bytes[i] >= '0' && bytes[i] <= '9') || (bytes[i] >= 'a' && bytes[i] <= 'f'))) return NO;
    }
    return YES;
}

static BOOL NFInteger(id object, int64_t *value) {
    if (![object isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)object) == CFBooleanGetTypeID()) return NO;
    NSNumber *number = object;
    int64_t result = number.longLongValue;
    if (number.doubleValue != (double)result) return NO;
    *value = result;
    return YES;
}

static NSDictionary *NFControl(NSData *data) {
    if (![data isKindOfClass:NSData.class] || !data.length || data.length > NFControlLimit) return nil;
    id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

static NSData *NFJSON(id value) {
    return [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:NULL] ?: NSData.data;
}

static NSString *NFHash(NSData *data) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
#pragma clang diagnostic pop
    NSMutableString *result = [NSMutableString stringWithCapacity:64];
    for (NSUInteger i = 0; i < sizeof(digest); ++i) [result appendFormat:@"%02x", digest[i]];
    return result;
}

static NSDictionary *NFAttempt(BOOL allowed, int error) {
    return @{@"allowed": @(allowed), @"errno": @(error)};
}

static NSDictionary *NFStageAttempt(BOOL allowed, int error, NSString *stage) {
    return @{@"allowed": @(allowed), @"errno": @(error), @"stage": stage};
}

static int NFOwnedControlDirectory(void) {
    int descriptor = open(NF_XPC_INHERITED_CONTROL_DIRECTORY, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat identity;
    if (descriptor < 0) return -1;
    if (fstat(descriptor, &identity) || !S_ISDIR(identity.st_mode) || identity.st_uid != geteuid() ||
        (identity.st_mode & 077) != 0) { close(descriptor); errno = EPERM; return -1; }
    return descriptor;
}

// Fixed whitelisted test state only; never a path selected by the RPC body.
// The first worker creates a one-byte marker; a fresh worker validates it.
static BOOL NFOnceConsumed(const char *leaf, unsigned char marker) {
    int directory = NFOwnedControlDirectory();
    if (directory < 0) _exit(78);
    int descriptor = openat(directory, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (descriptor >= 0) {
        struct stat before, after, linked;
        BOOL written = fstat(descriptor, &before) == 0 && S_ISREG(before.st_mode) &&
            before.st_uid == geteuid() && before.st_nlink == 1 && before.st_size == 0 &&
            NFWriteExact(descriptor, &marker, 1) && fstat(descriptor, &after) == 0 &&
            fstatat(directory, leaf, &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
            after.st_dev == before.st_dev && after.st_ino == before.st_ino &&
            after.st_uid == geteuid() && after.st_nlink == 1 && after.st_size == 1 &&
            after.st_dev == linked.st_dev && after.st_ino == linked.st_ino &&
            after.st_size == linked.st_size && linked.st_uid == geteuid() && linked.st_nlink == 1 && S_ISREG(linked.st_mode);
        close(descriptor);
        if (!written) { unlinkat(directory, leaf, 0); close(directory); _exit(78); }
        close(directory); return NO;
    }
    if (errno != EEXIST) { close(directory); _exit(78); }
    descriptor = openat(directory, leaf, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    struct stat before, after, linked;
    unsigned char value = 0;
    BOOL valid = descriptor >= 0 && fstat(descriptor, &before) == 0 && S_ISREG(before.st_mode) &&
        before.st_uid == geteuid() && before.st_nlink == 1 && before.st_size == 1 &&
        NFReadExact(descriptor, &value, 1) && value == marker && fstat(descriptor, &after) == 0 &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size &&
        before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
        before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec &&
        fstatat(directory, leaf, &linked, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(linked.st_mode) &&
        after.st_dev == linked.st_dev && after.st_ino == linked.st_ino && linked.st_uid == geteuid() &&
        linked.st_nlink == 1 && linked.st_size == 1;
    if (descriptor >= 0) close(descriptor);
    close(directory);
    if (!valid) _exit(78);
    return YES;
}

static NSDictionary *NFBoundary(void) {
    NSMutableDictionary *result = NSMutableDictionary.dictionary;
    int fd = open(NF_XPC_CANARY_PATH, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int error = fd < 0 ? errno : 0;
    BOOL readAllowed = NO;
    if (fd >= 0) {
        unsigned char byte = 0;
        ssize_t count = read(fd, &byte, 1);
        readAllowed = count == 1;
        if (count < 0) error = errno;
        close(fd);
    }
    result[@"outsideRead"] = NFStageAttempt(readAllowed, error, fd < 0 ? @"open" : @"read");
    // Never write the canary, even if the sandbox unexpectedly permits open.
    fd = open(NF_XPC_CANARY_PATH, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    error = fd < 0 ? errno : 0;
    result[@"outsideWritableOpen"] = NFStageAttempt(fd >= 0, error, @"open");
    if (fd >= 0) close(fd);
    NSString *created = [@NF_XPC_CANARY_PATH stringByAppendingString:@".created"];
    fd = open(created.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    error = fd < 0 ? errno : 0;
    result[@"outsideCreate"] = NFStageAttempt(fd >= 0, error, @"open");
    if (fd >= 0) { close(fd); unlink(created.fileSystemRepresentation); }

    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    error = socketFD < 0 ? errno : 0;
    result[@"ipv4Socket"] = NFAttempt(socketFD >= 0, error);
    if (socketFD >= 0) {
        struct sockaddr_in address = {0};
        address.sin_len = sizeof(address); address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(NF_XPC_LOOPBACK_PORT);
        int status = connect(socketFD, (struct sockaddr *)&address, sizeof(address));
        result[@"ipv4LoopbackConnect"] = NFStageAttempt(status == 0, status < 0 ? errno : 0, @"connect");
        close(socketFD);
    } else result[@"ipv4LoopbackConnect"] = NFStageAttempt(NO, error, @"socket");
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD >= 0) {
        struct sockaddr_in address = {0};
        address.sin_len = sizeof(address); address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = 0;
        int status = bind(socketFD, (struct sockaddr *)&address, sizeof(address));
        result[@"ipv4LoopbackBind"] = NFStageAttempt(status == 0, status < 0 ? errno : 0, @"bind");
        close(socketFD);
    } else result[@"ipv4LoopbackBind"] = NFStageAttempt(NO, errno, @"socket");

    socketFD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socketFD >= 0) {
        struct sockaddr_un address = {0};
        address.sun_len = sizeof(address); address.sun_family = AF_UNIX;
        NSString *path = [@NF_XPC_CANARY_PATH stringByAppendingString:@".socket"];
        const char *name = path.fileSystemRepresentation;
        if (strlen(name) >= sizeof(address.sun_path)) {
            result[@"unixOutsideBind"] = NFStageAttempt(NO, ENAMETOOLONG, @"path-length");
        } else {
            strlcpy(address.sun_path, name, sizeof(address.sun_path));
            int status = bind(socketFD, (struct sockaddr *)&address, sizeof(address));
            result[@"unixOutsideBind"] = NFStageAttempt(status == 0, status < 0 ? errno : 0, @"bind");
            if (status == 0) unlink(name);
        }
        close(socketFD);
    } else result[@"unixOutsideBind"] = NFStageAttempt(NO, errno, @"socket");

    NSString *container = [NSHomeDirectory() stringByAppendingPathComponent:
        [@"nf-owned-boundary-" stringByAppendingString:NSUUID.UUID.UUIDString]];
    fd = open(container.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    error = fd < 0 ? errno : 0;
    BOOL containerWrite = NO;
    if (fd >= 0) {
        unsigned char byte = 0x4e;
        ssize_t count = write(fd, &byte, 1);
        containerWrite = count == 1;
        if (count < 0) error = errno;
        close(fd); unlink(container.fileSystemRepresentation);
    }
    result[@"ownContainerWrite"] = NFAttempt(containerWrite, error);

    // A separately compiled, host-owned private child of the expected broker
    // container gives an actual positive control. Keep its one-byte output for
    // the preparation harness's independent post-run ownership/hash check.
    int directory = NFOwnedControlDirectory();
    int inheritedError = directory < 0 ? errno : 0;
    BOOL inheritedWrite = NO;
    if (directory >= 0) {
        int output = openat(directory, "write-control", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        inheritedError = output < 0 ? errno : 0;
        if (output >= 0) {
            unsigned char value = 0x4e;
            inheritedWrite = NFWriteExact(output, &value, 1);
            if (!inheritedWrite) inheritedError = errno;
            close(output);
        }
        close(directory);
    }
    result[@"inheritedContainerWrite"] = NFAttempt(inheritedWrite, inheritedError);

    // This process only waits for its own freshly spawned benign child. It never
    // adopts a PID from input, signals a process, or selects another executable.
    pid_t child = 0;
    char *argv[] = {"/usr/bin/true", NULL};
    char *env[] = {"PATH=/usr/bin:/bin", "LANG=C", NULL};
    int status = posix_spawn(&child, "/usr/bin/true", NULL, NULL, argv, env);
    BOOL executed = NO;
    if (status == 0) {
        int exitStatus = 0;
        pid_t waited;
        do { waited = waitpid(child, &exitStatus, 0); } while (waited < 0 && errno == EINTR);
        executed = waited == child && WIFEXITED(exitStatus) && WEXITSTATUS(exitStatus) == 0;
        if (!executed) status = waited < 0 ? errno : ECHILD;
    }
    result[@"systemTrueExecution"] = NFAttempt(executed, status);
    return result;
}

static BOOL NFTrueBooleanEntitlement(SecTaskRef task, CFStringRef name) {
    CFTypeRef value = task ? SecTaskCopyValueForEntitlement(task, name, NULL) : NULL;
    BOOL enabled = value && CFGetTypeID(value) == CFBooleanGetTypeID() && CFBooleanGetValue(value);
    if (value) CFRelease(value);
    return enabled;
}

int main(void) {
    @autoreleasepool {
        SecTaskRef task = SecTaskCreateFromSelf(NULL);
        BOOL sandbox = NFTrueBooleanEntitlement(task, CFSTR("com.apple.security.app-sandbox"));
        BOOL inherit = NFTrueBooleanEntitlement(task, CFSTR("com.apple.security.inherit"));
        if (task) CFRelease(task);
        if (!sandbox || !inherit) _exit(78);
        struct rlimit core = {0, 0}, cpu = {12, 13}, descriptors = {128, 128};
        if (setrlimit(RLIMIT_CORE, &core) || setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_NOFILE, &descriptors)) _exit(78);

        // Capture our own kernel identity before accepting any untrusted JSON.
        NSData *auditToken = NFDecoderCurrentAuditToken();
        if (!auditToken) _exit(78);
        atomic_init(&NFDeadlineNanoseconds, NFUptimeNanoseconds() + 15ull * NSEC_PER_SEC);
        atomic_init(&NFBodyComplete, false);
        pthread_t watchdog;
        if (pthread_create(&watchdog, NULL, NFWatchdogMain, NULL) || pthread_detach(watchdog)) _exit(78);

        NSDictionary *session = NFControl(NFReadFrame(NFControlLimit));
        int64_t version = 0, timeout = 0, deadline = 0;
        uint64_t now = NFUptimeNanoseconds();
        if (!session || !NFInteger(session[@"protocolVersion"], &version) || version != 2 ||
            !NFInteger(session[@"timeoutMilliseconds"], &timeout) || timeout < 1 || timeout > 120000 ||
            !NFInteger(session[@"deadlineUptimeNanoseconds"], &deadline) || deadline <= 0 ||
            (uint64_t)deadline <= now || (uint64_t)deadline - now > (uint64_t)timeout * NSEC_PER_MSEC ||
            !NFHex(session[@"nonce"], 32)) _exit(65);
        NSString *nonce = [session[@"nonce"] copy];
        atomic_store_explicit(&NFDeadlineNanoseconds, (uint64_t)deadline, memory_order_release);
        // Test-only variants allow an external, registered kernel observer to
        // cancel after the broker creates a worker but before host peer trust.
        // No runtime arbitrary control/path is added to the shipping protocol.
        if (NF_TEST_HELLO_DELAY_MS) {
            struct timespec delay = {.tv_sec = NF_TEST_HELLO_DELAY_MS / 1000,
                .tv_nsec = (NF_TEST_HELLO_DELAY_MS % 1000) * NSEC_PER_MSEC};
            while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
        }
        if (!NFWriteFrame(NFJSON(@{@"protocolVersion": @(NF_TEST_BAD_HELLO_VERSION ? 1 : 2), @"nonce": nonce,
                                   @"processIdentifier": @(getpid()),
                                   @"auditToken": [auditToken base64EncodedStringWithOptions:0]}), NFControlLimit)) _exit(74);

        NSDictionary *request = NFControl(NFReadFrame(NFControlLimit));
        int64_t count = -1;
        if (!request || !NFInteger(request[@"protocolVersion"], &version) || version != 2 ||
            !NFInteger(request[@"sourceByteCount"], &count) || count < 0 || count > NFInputLimit ||
            !NFHex(request[@"nonce"], 32) || ![request[@"nonce"] isEqualToString:nonce] ||
            !NFHex(request[@"sourceSHA256"], 64) || NFUptimeNanoseconds() >= (uint64_t)deadline) _exit(65);
        NSMutableData *bytes = [NSMutableData dataWithLength:(NSUInteger)count];
        if (!NFReadExact(STDIN_FILENO, bytes.mutableBytes, (size_t)count)) _exit(65);
        atomic_store_explicit(&NFBodyComplete, true, memory_order_release);
        // Reject already buffered trailing bytes before a fast synthetic result
        // can outrun the independent cancellation/deadline watchdog.
        if (!NFInputIdleAndOpen() || NFUptimeNanoseconds() >= (uint64_t)deadline) _exit(0);

        BOOL integrity = bytes.length == (NSUInteger)count && [NFHash(bytes) isEqualToString:request[@"sourceSHA256"]];
        if (!integrity) {
            NSData *failure = NFJSON(@{@"protocolVersion": @2, @"nonce": nonce,
                @"sourceSHA256": request[@"sourceSHA256"], @"sourceByteCount": @(count),
                @"failureCode": @"INTEGRITY_MISMATCH"});
            _exit(NFWriteFrame(failure, NFResponseLimit) ? 0 : 74);
        }
        if (NFUptimeNanoseconds() >= (uint64_t)deadline) _exit(0);
        NSString *mode = [[NSString alloc] initWithData:bytes encoding:NSUTF8StringEncoding] ?: @"";
        BOOL recoveryFixture = [@[@"NF_TEST_CRASH_ONCE", @"NF_TEST_MALFORMED_ONCE", @"NF_TEST_HANG_ONCE"] containsObject:mode];
        if ([mode isEqualToString:@"NF_TEST_CRASH_ONCE"]) {
            mode = NFOnceConsumed("crash-once", 0x43) ? @"NF_TEST_NORMAL" : @"NF_TEST_CRASH";
        } else if ([mode isEqualToString:@"NF_TEST_MALFORMED_ONCE"]) {
            mode = NFOnceConsumed("malformed-once", 0x4d) ? @"NF_TEST_NORMAL" : @"NF_TEST_MALFORMED";
        } else if ([mode isEqualToString:@"NF_TEST_HANG_ONCE"]) {
            mode = NFOnceConsumed("hang-once", 0x48) ? @"NF_TEST_NORMAL" : @"NF_TEST_HANG";
        }
        if (recoveryFixture) {
            // Fixed bounded settling interval for the independent test harness
            // to register exact broker/worker kernel objects, on both attempts.
            struct timespec remaining = {.tv_sec = 0, .tv_nsec = 150000000};
            while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {}
        }
        if ([mode isEqualToString:@"NF_TEST_CRASH"]) _exit(86);
        if ([mode isEqualToString:@"NF_TEST_HANG"]) { for (;;) pause(); }
        if ([mode isEqualToString:@"NF_TEST_MALFORMED"]) {
            _exit(NFWriteFrame([@"{bad-json}" dataUsingEncoding:NSUTF8StringEncoding], NFResponseLimit) ? 0 : 74);
        }
        if ([mode isEqualToString:@"NF_TEST_FLOOD"]) {
            // Deliberately declare and send 2 MiB + 1 for the broker's cap check.
            NSData *flood = [NSMutableData dataWithLength:NFResponseLimit + 1];
            _exit(NFWriteFrame(flood, NFResponseLimit + 1) ? 0 : 74);
        }
        NSString *text = @"synthetic parser worker fixture response";
        if ([mode isEqualToString:@"NF_TEST_BOUNDARY"]) {
            text = [[NSString alloc] initWithData:NFJSON(NFBoundary()) encoding:NSUTF8StringEncoding];
        }
        NSMutableDictionary *page = [@{@"pageNumber": @1, @"text": text, @"isTruncated": @NO,
            @"referenceLabel": @"Synthetic worker fixture", @"referenceKind": @"document"} mutableCopy];
        NSMutableDictionary *analysis = [@{@"schemaVersion": @1, @"contentKind": @"text", @"mimeType": @"text/plain", @"status": @"decoded",
            @"sourceSHA256": request[@"sourceSHA256"], @"sourceByteCount": @(count),
            @"textPages": @[page], @"rawMetadata": @[],
            @"warnings": @[@"Synthetic parser worker fixture; this is not the production parser binary."]} mutableCopy];
        NSDictionary *envelope = @{@"protocolVersion": @2, @"nonce": nonce,
            @"sourceSHA256": request[@"sourceSHA256"], @"sourceByteCount": @(count), @"analysis": analysis};
        if ([mode isEqualToString:@"NF_TEST_RESPONSE_CAP"]) {
            // JSON escapes U+0001 as six ASCII bytes. This fills the wire frame
            // while remaining below the separate 1 MiB derived-text limit.
            page[@"text"] = @"";
            analysis[@"warnings"] = @[@"Synthetic parser worker fixture; this is not the production parser binary.",
                                      @"Synthetic framed response byte count=0000000"];
            NSUInteger base = NFJSON(envelope).length;
            if (base >= NFResponseLimit) _exit(78);
            NSUInteger characters = (NFResponseLimit - base) / 6;
            unichar separator = 1;
            NSString *unit = [NSString stringWithCharacters:&separator length:1];
            page[@"text"] = [unit stringByPaddingToLength:characters withString:unit startingAtIndex:0];
            NSUInteger length = NFJSON(envelope).length;
            analysis[@"warnings"] = @[@"Synthetic parser worker fixture; this is not the production parser binary.",
                [NSString stringWithFormat:@"Synthetic framed response byte count=%07lu", (unsigned long)length]];
            if (length > NFResponseLimit || length < NFResponseLimit - 6 || characters > 1024 * 1024) _exit(78);
        }
        NSData *response = NFJSON(envelope);
        _exit(NFWriteFrame(response, NFResponseLimit) ? 0 : 74);
    }
}
