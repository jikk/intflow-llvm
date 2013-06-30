#include <stdlib.h>
#include <iconv.h>
#include <stdint.h>

div_t   __ioc_div(int numerator, int denominator);
ldiv_t  __ioc_ldiv(int numerator, int denominator);
lldiv_t __ioc_lldiv(int numerator, int denominator);
size_t __ioc_iconv(iconv_t cd,
                   char **inbuf, size_t *inbytesleft,
                   char **outbuf, size_t *outbytesleft);

#define XML_MSG                                     \
  "<structured_message>\n"                          \
  "<message_type>found_cwe</message_type>\n"        \
  "<cwe_entry_id>%s</cwe_entry_id>\n"               \
  "</structured_message>\n"                         \
  "<structured_message>\n"                          \
  "<message_type>controlled_exit</message_type>\n"  \
  "<test_case>%s</test_case>\n"                     \
  "</structured_message>\n"                         \
  "<structured_message>\n"                          \
  "<message_type>technical_impact</message_type>\n" \
  "<impact>%s</impact>\n"                           \
  "<test_case>%s</test_case>\n"                     \
  "</structured_message>\n"                         \
  "<!-- error class: %s   -->\n"                    \
  "<!-- file: %s   -->\n"                           \
  "<!-- line: %d   -->\n"                           \
  "<!-- column: %d   -->\n"                         \
  "<!-- value string: %s -->\n"

#define FNAME "/tmp/log.txt"
#define EXCLUDE_FNAME "/home/tm/ioc-llvm/ioc-helpers/exclude.files"

void __ioc____ioc_report_add_overflow(uint32_t line, uint32_t column,
                               const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T);
void __ioc___ioc_report_sub_overflow(uint32_t line, uint32_t column,
                               const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T);
void __ioc___ioc_report_mul_overflow(uint32_t line, uint32_t column,
                               const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T);
void __ioc___ioc_report_div_error(uint32_t line, uint32_t column,
                            const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T);
void __ioc___ioc_report_rem_error(uint32_t line, uint32_t column,
                            const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T);
void __ioc___ioc_report_shl_bitwidth(uint32_t line, uint32_t column,
                               const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T);
void __ioc___ioc_report_shr_bitwidth(uint32_t line, uint32_t column,
                               const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T);
void __ioc___ioc_report_shl_strict(uint32_t line, uint32_t column,
                             const char *filename, const char *exprstr,
                             uint64_t lval, uint64_t rval, uint8_t T);
void __ioc___ioc_report_conversion(uint32_t line, uint32_t column,
                             const char *filename,
                             const char *srcty, const char *canonsrcty,
                             const char *dstty, const char *canondstty,
                             uint64_t src, uint8_t S);
