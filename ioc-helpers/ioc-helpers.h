#include <stdlib.h>
#include <iconv.h>

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
  "<!-- colunm: %d   -->\n"                         \
  "<!-- value string: %s -->\n"

#define FNAME "/tmp/log.txt"
