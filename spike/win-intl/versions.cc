#include <icu.h>
#include <cstdio>
int main() {
  UVersionInfo v; char s[U_MAX_VERSION_STRING_LENGTH];
  u_getVersion(v); u_versionToString(v, s); std::printf("ICU %s\n", s);
  UErrorCode st = U_ZERO_ERROR; ulocdata_getCLDRVersion(v, &st); u_versionToString(v, s); std::printf("CLDR %s (%s)\n", s, u_errorName(st));
  u_getUnicodeVersion(v); u_versionToString(v, s); std::printf("Unicode %s\n", s);
  st = U_ZERO_ERROR; std::printf("tzdata %s (%s)\n", ucal_getTZDataVersion(&st), u_errorName(st));
  const char *styles[] = {"full","long","medium","short"};
  for (int t = 0; t < 4; ++t) {
    st = U_ZERO_ERROR; UDateFormat *f = udat_open((UDateFormatStyle)t, UDAT_NONE, "en_US", u"UTC", -1, nullptr, 0, &st);
    UChar p[128]; int n = udat_toPattern(f, false, p, 128, &st);
    std::printf("en_US time %-6s:", styles[t]); for (int i = 0; i < n; ++i) std::printf(p[i] < 0x80 ? "%c" : "<U+%04X>", p[i]); std::printf("\n"); udat_close(f);
  }
  return 0;
}
