// Test-only, never linked into or packaged with NativeForensics.
// Arms a Mach task right for the exact signed broker in an owned private app
// copy. A one-byte stdin trigger terminates that kernel object, never a PID.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *const NFIdentifier = @"org.nativeforensics.NFDocumentDecoderXPC";
static const char *NFSuffix = "/Contents/XPCServices/NFDocumentDecoderXPC.xpc/Contents/MacOS/NFDocumentDecoderXPC";

static void NFReportFailure(void) {
    static const char message[] = "Broker death helper receipt serialization/write failed.\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1);
    _exit(74);
}

static void NFReport(NSDictionary *value) {
    NSData *json = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:NULL];
    // The reader's 4096-byte cap includes the required newline.
    if (!json || json.length >= 4096) NFReportFailure();
    NSMutableData *line = [json mutableCopy];
    const unsigned char newline = '\n';
    [line appendBytes:&newline length:1];
    const unsigned char *cursor = line.bytes;
    NSUInteger remaining = line.length;
    while (remaining) {
        ssize_t count = write(STDOUT_FILENO, cursor, remaining);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) NFReportFailure();
        cursor += count; remaining -= (NSUInteger)count;
    }
}

static NSDictionary *NFInfo(SecStaticCodeRef code) {
    CFDictionaryRef information = NULL;
    OSStatus status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information);
    if (status != errSecSuccess || !information) return nil;
    return CFBridgingRelease(information);
}

static BOOL NFMinimalSandbox(NSDictionary *information) {
    NSDictionary *entitlements = information[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
    if (![entitlements isKindOfClass:NSDictionary.class] || entitlements.count != 1) return NO;
    id sandbox = entitlements[@"com.apple.security.app-sandbox"];
    return sandbox && CFGetTypeID((__bridge CFTypeRef)sandbox) == CFBooleanGetTypeID() &&
        CFBooleanGetValue((__bridge CFBooleanRef)sandbox);
}

static BOOL NFIdentity(NSDictionary *information, NSURL *expected, NSData *expectedCDHash) {
    id identifier = information[(__bridge NSString *)kSecCodeInfoIdentifier];
    id executable = information[(__bridge NSString *)kSecCodeInfoMainExecutable];
    id cdhash = information[(__bridge NSString *)kSecCodeInfoUnique];
    return [identifier isEqual:NFIdentifier] && [executable isKindOfClass:NSURL.class] &&
        [[executable URLByResolvingSymlinksInPath] isEqual:expected] &&
        [cdhash isKindOfClass:NSData.class] && (!expectedCDHash || [cdhash isEqual:expectedCDHash]) &&
        NFMinimalSandbox(information);
}

static BOOL NFPrivateOwnedApp(const char *argument, NSURL **executable, NSURL **service) {
    char resolved[PATH_MAX];
    if (!realpath(argument, resolved) || strcmp(resolved, argument)) return NO;
    NSString *app = [NSString stringWithUTF8String:resolved];
    if (![app.pathExtension isEqual:@"app"]) return NO;
    NSString *parent = app.stringByDeletingLastPathComponent;
    struct stat identity;
    if (lstat(parent.fileSystemRepresentation, &identity) || !S_ISDIR(identity.st_mode) ||
        identity.st_uid != geteuid() || (identity.st_mode & 077) != 0 ||
        ![parent.lastPathComponent hasPrefix:@"nf-xpc-runtime-"]) return NO;
    NSString *path = [app stringByAppendingString:[NSString stringWithUTF8String:NFSuffix]];
    char executableResolved[PATH_MAX];
    if (!realpath(path.fileSystemRepresentation, executableResolved) ||
        strcmp(path.fileSystemRepresentation, executableResolved)) return NO;
    *executable = [NSURL fileURLWithPath:path];
    *service = [NSURL fileURLWithPath:[app stringByAppendingPathComponent:@"Contents/XPCServices/NFDocumentDecoderXPC.xpc"]];
    return YES;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        int exitCode = 1;
        mach_port_t right = MACH_PORT_NULL;
        SecStaticCodeRef sealed = NULL;
        SecCodeRef peer = NULL;
        SecRequirementRef requirement = NULL;
        do {
            char *tail = NULL;
            long number = argc == 3 ? strtol(argv[1], &tail, 10) : 0;
            NSURL *executable = nil, *service = nil;
            if (argc != 3 || !tail || *tail || number <= 1 || number > INT_MAX ||
                !NFPrivateOwnedApp(argv[2], &executable, &service)) {
                NFReport(@{@"status": @"refused", @"phase": @"arguments"}); break;
            }
            OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)service, kSecCSDefaultFlags, &sealed);
            if (status == errSecSuccess) status = SecStaticCodeCheckValidity(sealed, kSecCSDefaultFlags, NULL);
            NSDictionary *staticInfo = sealed ? NFInfo(sealed) : nil;
            NSData *cdhash = staticInfo[(__bridge NSString *)kSecCodeInfoUnique];
            if (status != errSecSuccess || !NFIdentity(staticInfo, executable, nil) ||
                SecCodeCopyDesignatedRequirement(sealed, kSecCSDefaultFlags, &requirement) != errSecSuccess) {
                NFReport(@{@"status": @"refused", @"phase": @"sealed-identity", @"securityStatus": @(status)}); break;
            }
            kern_return_t result = task_for_pid(mach_task_self(), (pid_t)number, &right);
            if (result != KERN_SUCCESS || right == MACH_PORT_NULL) {
                // This test does not add get-task-allow, disable SIP, request a
                // privilege grant, or fall back to a numeric PID signal.
                NFReport(@{@"status": @"unavailable", @"phase": @"task-for-pid", @"kernelStatus": @(result)});
                exitCode = 77; break;
            }
            audit_token_t token;
            mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
            result = task_info(right, TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
            if (result != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT ||
                audit_token_to_pid(token) != (pid_t)number || audit_token_to_euid(token) != geteuid()) {
                NFReport(@{@"status": @"refused", @"phase": @"kernel-identity", @"kernelStatus": @(result)}); break;
            }
            NSData *audit = [NSData dataWithBytes:&token length:sizeof(token)];
            NSDictionary *attributes = @{(__bridge NSString *)kSecGuestAttributeAudit: audit};
            status = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attributes, kSecCSDefaultFlags, &peer);
            if (status == errSecSuccess) status = SecCodeCheckValidity(peer, kSecCSDefaultFlags, requirement);
            if (status != errSecSuccess || !NFIdentity(peer ? NFInfo((SecStaticCodeRef)peer) : nil, executable, cdhash)) {
                NFReport(@{@"status": @"refused", @"phase": @"live-identity", @"securityStatus": @(status)}); break;
            }
            NFReport(@{@"status": @"armed", @"processIdentifier": @(number),
                @"auditToken": [audit base64EncodedStringWithOptions:0], @"executable": executable.path,
                @"codeSigningCDHash": [cdhash base64EncodedStringWithOptions:0]});
            struct pollfd trigger = {.fd = STDIN_FILENO, .events = POLLIN | POLLHUP};
            int ready;
            do { ready = poll(&trigger, 1, 30000); } while (ready < 0 && errno == EINTR);
            unsigned char command = 0;
            ssize_t readCount = ready > 0 ? read(STDIN_FILENO, &command, 1) : 0;
            if (readCount != 1 || command != 'T') {
                NFReport(@{@"status": @"cancelled", @"phase": @"trigger"}); exitCode = 0; break;
            }
            audit_token_t currentToken;
            count = TASK_AUDIT_TOKEN_COUNT;
            result = task_info(right, TASK_AUDIT_TOKEN, (task_info_t)&currentToken, &count);
            if (result != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT ||
                memcmp(&currentToken, &token, sizeof(token)) != 0 ||
                SecCodeCheckValidity(peer, kSecCSDefaultFlags, requirement) != errSecSuccess) {
                NFReport(@{@"status": @"refused", @"phase": @"changed-task-identity", @"kernelStatus": @(result)}); break;
            }
            // The retained send right addresses the validated kernel task even
            // if it has exited or its numeric PID is subsequently reused.
            result = task_terminate(right);
            NFReport(@{@"status": result == KERN_SUCCESS ? @"terminated" : @"failed",
                @"kernelStatus": @(result), @"processIdentifier": @(number)});
            exitCode = result == KERN_SUCCESS ? 0 : 1;
        } while (0);
        if (peer) CFRelease(peer);
        if (requirement) CFRelease(requirement);
        if (sealed) CFRelease(sealed);
        if (right != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), right);
        return exitCode;
    }
}
