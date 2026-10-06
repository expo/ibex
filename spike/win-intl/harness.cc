// Spike harness: drive the ibex2 Intl shims' C entry points directly.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <windows.h>
extern "C" {
char *ibex2_icu_default_locale();
char *ibex2_icu_canonical_locale(const char *);
char *ibex2_icu_best_available_locale(const char *);
char *ibex2_icu_default_numbering_system(const char *);
int32_t ibex2_icu_currency_digits(const char *);
void *ibex2_icu_number_formatter_create(const char *, const char *);
void ibex2_icu_number_formatter_destroy(void *);
void *ibex2_icu_number_format_double(const void *, double);
const char *ibex2_icu_number_result_text(const void *, size_t *);
size_t ibex2_icu_number_result_field_count(const void *);
int ibex2_icu_number_result_field(const void *, size_t, int32_t *, size_t *, size_t *);
void ibex2_icu_number_result_destroy(void *);
void ibex2_icu_string_destroy(char *);
int ibex2_icu_case_map(uint8_t, const char *, size_t, const uint16_t *, size_t, uint16_t *, size_t, size_t *);
char *ibex2_icu_datetime_default_calendar(const char *);
int ibex2_icu_datetime_default_hour_cycle(const char *);
char *ibex2_icu_datetime_canonical_time_zone(const char *);
void *ibex2_icu_datetime_formatter_create(const char *, const char *, const char *, int32_t, int32_t);
void ibex2_icu_datetime_formatter_destroy(void *);
const char *ibex2_icu_datetime_formatter_pattern(const void *, size_t *);
void *ibex2_icu_datetime_format(const void *, double);
const char *ibex2_icu_datetime_result_text(const void *, size_t *);
void ibex2_icu_datetime_result_destroy(void *);
}
static void str(const char *label, char *v) { std::printf("%s = %s\n", label, v ? v : "(null)"); if (v) ibex2_icu_string_destroy(v); }
static void num(const char *loc, const char *skel, double x) {
  void *f = ibex2_icu_number_formatter_create(loc, skel);
  if (!f) { std::printf("number[%s|%s] create FAILED\n", loc, skel); return; }
  void *r = ibex2_icu_number_format_double(f, x);
  size_t n = 0; const char *t = r ? ibex2_icu_number_result_text(r, &n) : nullptr;
  std::printf("number[%s|%s](%g) = %.*s  fields=%zu\n", loc, skel, x, (int)n, t ? t : "", r ? ibex2_icu_number_result_field_count(r) : 0);
  for (size_t i = 0; r && i < ibex2_icu_number_result_field_count(r); ++i) {
    int32_t fld = 0; size_t b = 0, e = 0;
    ibex2_icu_number_result_field(r, i, &fld, &b, &e);
    std::printf("    field %d [%zu,%zu)\n", fld, b, e);
  }
  if (r) ibex2_icu_number_result_destroy(r);
  ibex2_icu_number_formatter_destroy(f);
}
static void dt(const char *loc, const char *tz, const char *skel, int ds, int ts, double ms) {
  void *f = ibex2_icu_datetime_formatter_create(loc, tz, skel, ds, ts);
  if (!f) { std::printf("datetime[%s] create FAILED\n", loc); return; }
  size_t pn = 0; const char *p = ibex2_icu_datetime_formatter_pattern(f, &pn);
  void *r = ibex2_icu_datetime_format(f, ms);
  size_t n = 0; const char *t = r ? ibex2_icu_datetime_result_text(r, &n) : nullptr;
  std::printf("datetime[%s|%s|%s|%d,%d] pattern=%.*s -> %.*s\n", loc, tz, skel ? skel : "-", ds, ts, (int)pn, p, (int)n, t ? t : "");
  if (r) ibex2_icu_datetime_result_destroy(r);
  ibex2_icu_datetime_formatter_destroy(f);
}
static void cm(uint8_t mode, const char *loc, const char16_t *in) {
  size_t len = std::char_traits<char16_t>::length(in), outlen = 0; uint16_t out[64];
  int rc = ibex2_icu_case_map(mode, loc, std::strlen(loc), (const uint16_t *)in, len, out, 64, &outlen);
  std::printf("case[%s,%s] rc=%d ->", mode ? "upper" : "lower", loc, rc);
  for (size_t i = 0; i < outlen; ++i) std::printf(" U+%04X", out[i]);
  std::printf("\n");
}
int main() {
  SetConsoleOutputCP(CP_UTF8);
  str("default_locale", ibex2_icu_default_locale());
  str("canonical(EN-us)", ibex2_icu_canonical_locale("EN-us"));
  str("best_available(de-DE)", ibex2_icu_best_available_locale("de-DE"));
  str("best_available(tr)", ibex2_icu_best_available_locale("tr"));
  str("numbering(ar-EG)", ibex2_icu_default_numbering_system("ar-EG"));
  std::printf("currency_digits(JPY)=%d (USD)=%d\n", ibex2_icu_currency_digits("JPY"), ibex2_icu_currency_digits("USD"));
  num("de-DE", "", 1234.5);
  num("en-US", "currency/USD", 12.5);
  num("ja-JP", "currency/JPY", 1234.5);
  num("en-IN", "", 1234567.891);
  num("de-DE", "", -1234.5);
  num("en", "compact-short", 1234567);
  num("en", "percent precision-integer", 0.5);
  num("en", "measure-unit/length-kilometer unit-width-short", 50);
  str("default_calendar(th-TH)", ibex2_icu_datetime_default_calendar("th-TH"));
  std::printf("hour_cycle(en-US)=%d (de-DE)=%d\n", ibex2_icu_datetime_default_hour_cycle("en-US"), ibex2_icu_datetime_default_hour_cycle("de-DE"));
  str("canonical_tz(asia/calcutta)", ibex2_icu_datetime_canonical_time_zone("asia/calcutta"));
  str("canonical_tz(default)", ibex2_icu_datetime_canonical_time_zone(nullptr));
  dt("en-US", "UTC", nullptr, 2, -1, 0);
  dt("en-US", "UTC", nullptr, 2, 2, 0);
  dt("de-DE", "Europe/Berlin", "yMMMMdjm", -1, -1, 0);
  cm(1, "tr", u"i");
  cm(1, "en", u"i");
  cm(1, "und", u"\u00e9");
  cm(0, "tr", u"I");
  cm(1, "de", u"\u00df");
  return 0;
}
