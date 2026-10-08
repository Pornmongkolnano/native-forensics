#import "NFDecoderIPC.h"
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <string.h>
#include <unistd.h>

NSString * const NFDocumentDecoderXPCServiceName = @"org.nativeforensics.NFDocumentDecoderXPC";

static BOOL NFDecoderReadAuditToken(NSData *data, audit_token_t *token) {
    if (data.length != sizeof(*token)) {
        return NO;
    }
    memcpy(token, data.bytes, sizeof(*token));
    return audit_token_to_pid(*token) > 0;
}

NSData * _Nullable NFDecoderCurrentAuditToken(void) {
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t status = task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                                    (task_info_t)&token, &count);
    if (status != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT ||
        audit_token_to_pid(token) != getpid() ||
        audit_token_to_euid(token) != geteuid()) {
        return nil;
    }
    return [NSData dataWithBytes:&token length:sizeof(token)];
}

pid_t NFDecoderAuditTokenPID(NSData *data) {
    audit_token_t token = {0};
    return NFDecoderReadAuditToken(data, &token) ? audit_token_to_pid(token) : (pid_t)-1;
}

uid_t NFDecoderAuditTokenUID(NSData *data) {
    audit_token_t token = {0};
    return NFDecoderReadAuditToken(data, &token) ? audit_token_to_euid(token) : (uid_t)-1;
}
