#import <Foundation/Foundation.h>
#include <sys/types.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString * const NFDocumentDecoderXPCServiceName;

/// The decoder boundary carries bounded, explicitly encoded data only.
@protocol NFDocumentDecoderXPC <NSObject>
- (void)beginSession:(NSData *)request reply:(void (^)(NSData *response))reply;
- (void)decodeDocument:(NSData *)document
               request:(NSData *)request
                 reply:(void (^)(NSData *response))reply;
- (void)cancelSession:(NSData *)nonce;
@end

/// Returns this process's kernel audit token, or nil when it cannot be read.
/// Capture this before decoding untrusted content and retain an immutable copy.
FOUNDATION_EXPORT NSData * _Nullable NFDecoderCurrentAuditToken(void);

/// Returns -1 for a malformed token. This parses identity; it does not authenticate it.
FOUNDATION_EXPORT pid_t NFDecoderAuditTokenPID(NSData *token);

/// Returns (uid_t)-1 for a malformed token; the result is the effective UID.
FOUNDATION_EXPORT uid_t NFDecoderAuditTokenUID(NSData *token);

NS_ASSUME_NONNULL_END
