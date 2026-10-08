// Synthetic runtime fixture only. Never package this as the shipping parser.
// Paths/port are compile-time constants for resources owned by its test harness.
#import <Foundation/Foundation.h>
#import <Security/SecTask.h>
#import "NFDecoderIPC.h"
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <spawn.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NF_XPC_CANARY_PATH
#error "Compile with a fixed path to an owned synthetic outside-container canary."
#endif
#ifndef NF_XPC_LOOPBACK_PORT
#error "Compile with the ephemeral port of the harness-owned loopback listener."
#endif

static const NSUInteger NFInputLimit = 128 * 1024 * 1024;
static const NSUInteger NFControlLimit = 4096;
static const NSUInteger NFResponseLimit = 2 * 1024 * 1024;

static uint64_t NFUptimeNanoseconds(void) {
    static mach_timebase_info_data_t scale;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ mach_timebase_info(&scale); });
    return (uint64_t)(((__uint128_t)mach_absolute_time() * scale.numer) / scale.denom);
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
    result[@"outsideRead"] = NFAttempt(readAllowed, error);
    // A successful writable open is enough to expose the policy breach. Do not
    // write to the canary even if the test unexpectedly has that permission.
    fd = open(NF_XPC_CANARY_PATH, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    error = fd < 0 ? errno : 0;
    result[@"outsideWritableOpen"] = NFAttempt(fd >= 0, error);
    if (fd >= 0) close(fd);
    NSString *created = [@NF_XPC_CANARY_PATH stringByAppendingString:@".created"];
    fd = open(created.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    error = fd < 0 ? errno : 0;
    result[@"outsideCreate"] = NFAttempt(fd >= 0, error);
    if (fd >= 0) { close(fd); unlink(created.fileSystemRepresentation); }

    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    error = socketFD < 0 ? errno : 0;
    result[@"ipv4Socket"] = NFAttempt(socketFD >= 0, error);
    if (socketFD >= 0) {
        struct sockaddr_in address = {0};
        address.sin_len = sizeof(address); address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(NF_XPC_LOOPBACK_PORT);
        int status = connect(socketFD, (struct sockaddr *)&address, sizeof(address));
        result[@"ipv4LoopbackConnect"] = NFAttempt(status == 0, status < 0 ? errno : 0);
        close(socketFD);
    } else result[@"ipv4LoopbackConnect"] = NFAttempt(NO, error);
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD >= 0) {
        struct sockaddr_in address = {0};
        address.sin_len = sizeof(address); address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = 0;
        int status = bind(socketFD, (struct sockaddr *)&address, sizeof(address));
        result[@"ipv4LoopbackBind"] = NFAttempt(status == 0, status < 0 ? errno : 0);
        close(socketFD);
    } else result[@"ipv4LoopbackBind"] = NFAttempt(NO, errno);

    socketFD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socketFD >= 0) {
        struct sockaddr_un address = {0};
        address.sun_len = sizeof(address); address.sun_family = AF_UNIX;
        NSString *path = [@NF_XPC_CANARY_PATH stringByAppendingString:@".socket"];
        const char *name = path.fileSystemRepresentation;
        if (strlen(name) >= sizeof(address.sun_path)) {
            result[@"unixOutsideBind"] = NFAttempt(NO, ENAMETOOLONG);
        } else {
            strlcpy(address.sun_path, name, sizeof(address.sun_path));
            int status = bind(socketFD, (struct sockaddr *)&address, sizeof(address));
            result[@"unixOutsideBind"] = NFAttempt(status == 0, status < 0 ? errno : 0);
            if (status == 0) unlink(name);
        }
        close(socketFD);
    } else result[@"unixOutsideBind"] = NFAttempt(NO, errno);

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

@interface NFFixtureWorker : NSObject <NFDocumentDecoderXPC>
@property(nonatomic, copy) NSString *nonce;
@property(nonatomic) uint64_t deadline;
@property(nonatomic) BOOL beganDecode;
@property(nonatomic, strong) dispatch_source_t watchdog;
@property(nonatomic, strong) dispatch_queue_t decoderQueue;
@end

@implementation NFFixtureWorker
- (instancetype)init {
    if ((self = [super init])) {
        _decoderQueue = dispatch_queue_create("org.nativeforensics.test-only-decoder", DISPATCH_QUEUE_SERIAL);
        _deadline = NFUptimeNanoseconds() + 15ull * NSEC_PER_SEC;
        _watchdog = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0));
        __weak NFFixtureWorker *weakSelf = self;
        dispatch_source_set_event_handler(_watchdog, ^{
            NFFixtureWorker *strongSelf = weakSelf;
            if (!strongSelf) return;
            @synchronized(strongSelf) {
                if (NFUptimeNanoseconds() >= strongSelf.deadline) _exit(0);
            }
        });
        dispatch_source_set_timer(_watchdog, dispatch_time(DISPATCH_TIME_NOW, 15ull * NSEC_PER_SEC), DISPATCH_TIME_FOREVER, NSEC_PER_MSEC);
        dispatch_resume(_watchdog);
    }
    return self;
}
- (void)beginSession:(NSData *)data reply:(void (^)(NSData *))reply {
    NSDictionary *request = NFControl(data);
    int64_t version = 0, timeout = 0, deadline = 0;
    uint64_t now = NFUptimeNanoseconds();
    if (!request || !NFInteger(request[@"protocolVersion"], &version) || version != 1 ||
        !NFInteger(request[@"timeoutMilliseconds"], &timeout) || timeout < 1 || timeout > 120000 ||
        !NFInteger(request[@"deadlineUptimeNanoseconds"], &deadline) || deadline <= 0 ||
        (uint64_t)deadline <= now || (uint64_t)deadline - now > (uint64_t)timeout * NSEC_PER_MSEC ||
        !NFHex(request[@"nonce"], 32)) { reply(NSData.data); return; }
    NSData *token = NFDecoderCurrentAuditToken();
    if (!token) { reply(NSData.data); return; }
    @synchronized(self) {
        if (self.nonce) { reply(NSData.data); return; }
        self.nonce = request[@"nonce"];
        self.deadline = (uint64_t)deadline;
        uint64_t updatedNow = NFUptimeNanoseconds();
        if (updatedNow >= self.deadline) _exit(0);
        dispatch_source_set_timer(self.watchdog, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.deadline - updatedNow)), DISPATCH_TIME_FOREVER, NSEC_PER_MSEC);
    }
    reply(NFJSON(@{@"protocolVersion": @1, @"nonce": request[@"nonce"], @"processIdentifier": @(getpid()),
                   @"auditToken": [token base64EncodedStringWithOptions:0]}));
}
- (void)decodeDocument:(NSData *)document request:(NSData *)data reply:(void (^)(NSData *))reply {
    NSDictionary *request = NFControl(data);
    int64_t version = 0, count = -1;
    if (![document isKindOfClass:NSData.class] || document.length > NFInputLimit || !request ||
        !NFInteger(request[@"protocolVersion"], &version) || version != 1 ||
        !NFInteger(request[@"sourceByteCount"], &count) || count < 0 || count > NFInputLimit ||
        !NFHex(request[@"nonce"], 32) || !NFHex(request[@"sourceSHA256"], 64)) { reply(NSData.data); return; }
    uint64_t deadline;
    @synchronized(self) {
        if (!self.nonce || ![request[@"nonce"] isEqualToString:self.nonce] || self.beganDecode ||
            NFUptimeNanoseconds() >= self.deadline) { reply(NSData.data); return; }
        self.beganDecode = YES;
        deadline = self.deadline;
    }
    NSData *bytes = [document copy];
    dispatch_async(self.decoderQueue, ^{
        if (NFUptimeNanoseconds() >= deadline) _exit(0);
        BOOL integrity = bytes.length == (NSUInteger)count && [NFHash(bytes) isEqualToString:request[@"sourceSHA256"]];
        if (!integrity) {
            reply(NFJSON(@{@"protocolVersion": @1, @"nonce": request[@"nonce"], @"sourceSHA256": request[@"sourceSHA256"],
                           @"sourceByteCount": @(count), @"failureCode": @"INTEGRITY_MISMATCH"}));
            return;
        }
        if (NFUptimeNanoseconds() >= deadline) _exit(0);
        NSString *mode = [[NSString alloc] initWithData:bytes encoding:NSUTF8StringEncoding] ?: @"";
        if ([mode isEqualToString:@"NF_TEST_CRASH"]) _exit(86);
        if ([mode isEqualToString:@"NF_TEST_HANG"]) { for (;;) pause(); }
        if ([mode isEqualToString:@"NF_TEST_MALFORMED"]) { reply([@"{bad-json}" dataUsingEncoding:NSUTF8StringEncoding]); return; }
        if ([mode isEqualToString:@"NF_TEST_FLOOD"]) {
            reply([NSMutableData dataWithLength:NFResponseLimit + 1]); return;
        }
        NSString *text = @"synthetic XPC fixture response";
        if ([mode isEqualToString:@"NF_TEST_BOUNDARY"]) text = [[NSString alloc] initWithData:NFJSON(NFBoundary()) encoding:NSUTF8StringEncoding];
        NSDictionary *analysis = @{@"schemaVersion": @1, @"contentKind": @"text", @"mimeType": @"text/plain", @"status": @"decoded",
            @"sourceSHA256": request[@"sourceSHA256"], @"sourceByteCount": @(count),
            @"textPages": @[@{@"pageNumber": @1, @"text": text, @"isTruncated": @NO,
                              @"referenceLabel": @"Synthetic fixture", @"referenceKind": @"document"}],
            @"rawMetadata": @[], @"warnings": @[@"Synthetic XPC fixture; this is not the production parser binary."]};
        NSData *response = NFJSON(@{@"protocolVersion": @1, @"nonce": request[@"nonce"],
            @"sourceSHA256": request[@"sourceSHA256"], @"sourceByteCount": @(count), @"analysis": analysis});
        reply(response.length <= NFResponseLimit ? response : NSData.data);
    });
}
- (void)cancelSession:(NSData *)nonce {
    if (![nonce isKindOfClass:NSData.class] || nonce.length != 32) return;
    @synchronized(self) {
        if (self.nonce && [nonce isEqualToData:[self.nonce dataUsingEncoding:NSUTF8StringEncoding]]) _exit(0);
    }
}
@end

@interface NFFixtureListener : NSObject <NSXPCListenerDelegate>
@property(nonatomic) BOOL acceptedConnection;
@end
@implementation NFFixtureListener
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    if (connection.effectiveUserIdentifier != geteuid()) return NO;
    @synchronized(self) {
        if (self.acceptedConnection) return NO;
        self.acceptedConnection = YES;
    }
    [connection setCodeSigningRequirement:@"identifier \"io.github.pornmongkolnano.nativeforensics\""];
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(NFDocumentDecoderXPC)];
    connection.exportedObject = [[NFFixtureWorker alloc] init];
    connection.invalidationHandler = ^{ _exit(0); };
    connection.interruptionHandler = ^{ _exit(0); };
    [connection resume];
    return YES;
}
@end

int main(void) {
    @autoreleasepool {
        SecTaskRef task = SecTaskCreateFromSelf(NULL);
        CFTypeRef sandbox = task ? SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.security.app-sandbox"), NULL) : NULL;
        BOOL enabled = sandbox && CFGetTypeID(sandbox) == CFBooleanGetTypeID() && CFBooleanGetValue(sandbox);
        if (sandbox) CFRelease(sandbox);
        if (task) CFRelease(task);
        if (!enabled) _exit(78);
        struct rlimit core = {0, 0}, cpu = {12, 13}, descriptors = {128, 128};
        setrlimit(RLIMIT_CORE, &core); setrlimit(RLIMIT_CPU, &cpu); setrlimit(RLIMIT_NOFILE, &descriptors);
        NFFixtureListener *delegate = [[NFFixtureListener alloc] init];
        NSXPCListener *listener = NSXPCListener.serviceListener;
        listener.delegate = delegate;
        [listener resume];
        dispatch_main();
    }
}
