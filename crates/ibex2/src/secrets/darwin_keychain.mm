// The Keychain behind the SecretStore trait: the platform half of LLP 0069 §3.
//
// Generic-password items: kSecAttrService is the app's identity, kSecAttrAccount
// the secret's name, the value the data. `set` updates an existing item and
// adds one when there is none; `forget` treats "not found" as done.
//
// iOS: the data-protection keychain, AfterFirstUnlockThisDeviceOnly — readable
// after the first unlock (a background fetch can use it), never restored to
// another device from a backup. macOS: the login keychain, on purpose —
// kSecUseDataProtectionKeychain would need an application-identifier
// entitlement (a bundle and a provisioning profile), and the login keychain
// serves a bare signed binary. Its ACL trusts the creating app by its code
// signature's designated requirement, so a consumer that rebuilds must sign
// with a stable identity or be asked again after every build (exact2 LLP 1018
// D7).
//
// @ref LLP 0069#3-the-backends — the Keychain, and why the login keychain on macOS

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

char *dup_utf8(NSString *value) {
  if (value == nil) {
    return nullptr;
  }
  const char *raw = [value UTF8String];
  if (raw == nullptr) {
    return nullptr;
  }
  size_t len = std::strlen(raw);
  char *out = static_cast<char *>(std::malloc(len + 1));
  if (out != nullptr) {
    std::memcpy(out, raw, len + 1);
  }
  return out;
}

#if TARGET_OS_OSX
// Whether the main executable's directory is plainly not a bundle: on a
// case-insensitive volume, not a platform executables folder (whose bundle is
// further up) nor a framework, and holding none of the names CoreFoundation
// looks for in a bundle (each compared without case, so `lstat` finds them).
// Whether CFProcessPath was set when this image loaded, which CoreFoundation
// may have read and kept even if the process unsets it before asking
const bool process_path_at_load = getenv("CFProcessPath") != nullptr;

bool outside_any_bundle() {
  // CoreFoundation takes its process path from CFProcessPath when it is set
  if (process_path_at_load || getenv("CFProcessPath") != nullptr) {
    return false;
  }
  uint32_t size = 0;
  _NSGetExecutablePath(nullptr, &size);
  std::string path(size, '\0');
  if (_NSGetExecutablePath(path.data(), &size) != 0) {
    return false;
  }
  // The path as executed, symlinks unresolved, as CoreFoundation takes it
  NSString *directory = [NSString stringWithUTF8String:path.c_str()]
                            .stringByDeletingLastPathComponent;
  if (pathconf(directory.fileSystemRepresentation, _PC_CASE_SENSITIVE) != 0) {
    return false;
  }
  for (NSString *name in @[ @"MacOS", @"Mac OS X", @"MacOSClassic", @"Mac OS 8" ]) {
    if ([directory.lastPathComponent caseInsensitiveCompare:name] ==
        NSOrderedSame) {
      return false;
    }
  }
  if ([directory.pathExtension caseInsensitiveCompare:@"framework"] ==
      NSOrderedSame) {
    return false;
  }
  for (NSString *name in @[ @"Contents", @"Resources", @"Support Files",
                            @"Info.plist", @"Info-macos.plist" ]) {
    struct stat info;
    NSString *marker = [directory stringByAppendingPathComponent:name];
    if (lstat(marker.fileSystemRepresentation, &info) == 0) {
      return false;
    }
  }
  return true;
}

// CFBundleIdentifier from the main executable's `__TEXT,__info_plist`
// section, or nil when it has none
NSString *embedded_identifier() {
  unsigned long length = 0;
  const uint8_t *bytes = getsectiondata(
      reinterpret_cast<const struct mach_header_64 *>(_dyld_get_image_header(0)),
      "__TEXT", "__info_plist", &length);
  if (bytes == nullptr) {
    return nil;
  }
  NSData *data = [NSData dataWithBytesNoCopy:(void *)bytes
                                      length:length
                                freeWhenDone:NO];
  id info = [NSPropertyListSerialization propertyListWithData:data
                                                      options:NSPropertyListImmutable
                                                       format:nil
                                                        error:nil];
  id identifier =
      [info isKindOfClass:[NSDictionary class]] ? info[@"CFBundleIdentifier"] : nil;
  return [identifier isKindOfClass:[NSString class]] ? identifier : nil;
}
#endif

char *status_message(OSStatus status) {
  CFStringRef message = SecCopyErrorMessageString(status, nullptr);
  NSString *text = message != nullptr ? (__bridge_transfer NSString *)message : nil;
  if (text == nil) {
    text = [NSString stringWithFormat:@"OSStatus %d", static_cast<int>(status)];
  }
  return dup_utf8(text);
}

NSMutableDictionary *query_for(const char *service, const char *name) {
  NSMutableDictionary *query = [NSMutableDictionary dictionary];
  query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
  query[(__bridge id)kSecAttrService] = [NSString stringWithUTF8String:service];
  query[(__bridge id)kSecAttrAccount] = [NSString stringWithUTF8String:name];
  return query;
}

} // namespace

extern "C" {

int ibex2_darwin_keychain_get(const char *service, const char *name, unsigned char **out_value,
                              size_t *out_len, char **out_error) {
  @autoreleasepool {
    *out_value = nullptr;
    *out_len = 0;
    *out_error = nullptr;
    NSMutableDictionary *query = query_for(service, name);
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef result = nullptr;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound) {
      return 1;
    }
    if (status != errSecSuccess) {
      *out_error = status_message(status);
      return -1;
    }
    NSData *data = (__bridge_transfer NSData *)result;
    unsigned char *bytes = static_cast<unsigned char *>(std::malloc(data.length + 1));
    if (bytes == nullptr) {
      *out_error = dup_utf8(@"out of memory");
      return -1;
    }
    std::memcpy(bytes, data.bytes, data.length);
    *out_value = bytes;
    *out_len = data.length;
    return 0;
  }
}

int ibex2_darwin_keychain_set(const char *service, const char *name, const unsigned char *value,
                              size_t len, char **out_error) {
  @autoreleasepool {
    *out_error = nullptr;
    NSData *data = [NSData dataWithBytes:value length:len];
    NSMutableDictionary *query = query_for(service, name);
    NSDictionary *update = @{(__bridge id)kSecValueData : data};
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
    if (status == errSecItemNotFound) {
      NSMutableDictionary *item = query_for(service, name);
      item[(__bridge id)kSecValueData] = data;
#if TARGET_OS_IPHONE
      item[(__bridge id)kSecAttrAccessible] =
          (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
#endif
      status = SecItemAdd((__bridge CFDictionaryRef)item, nullptr);
    }
    if (status != errSecSuccess) {
      *out_error = status_message(status);
      return -1;
    }
    return 0;
  }
}

int ibex2_darwin_keychain_forget(const char *service, const char *name, char **out_error) {
  @autoreleasepool {
    *out_error = nullptr;
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query_for(service, name));
    if (status != errSecSuccess && status != errSecItemNotFound) {
      *out_error = status_message(status);
      return -1;
    }
    return 0;
  }
}

// The main bundle's identifier. On macOS, NSBundle finds the main bundle by
// listing the executable's directory, and a build tree's directory can hold
// hundreds of thousands of files: seconds of system time in every process.
// When that directory is plainly not a bundle by CoreFoundation's own markers
// (CFBundle.c `_CFBundleCopyBundleURLForExecutablePath`, CFBundle_Resources.c
// `_CFBundleGetBundleVersionForURL`, CFBundle_InfoPlist.c), the identifier can
// only come from an Info.plist embedded in the executable, which this reads.
// Anything else, a case-sensitive volume or a CFProcessPath override included,
// asks NSBundle.
char *ibex2_darwin_bundle_identifier(void) {
  @autoreleasepool {
#if TARGET_OS_OSX
    if (outside_any_bundle()) {
      return dup_utf8(embedded_identifier());
    }
#endif
    return dup_utf8([[NSBundle mainBundle] bundleIdentifier]);
  }
}

} // extern "C"
