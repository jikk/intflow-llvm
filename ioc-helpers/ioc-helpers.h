#include <stdlib.h>
#include <iconv.h>

div_t   __ioc_div(int numerator, int denominator);
ldiv_t  __ioc_ldiv(int numerator, int denominator);
lldiv_t __ioc_lldiv(int numerator, int denominator);
size_t __ioc_iconv(iconv_t cd,
                   char **inbuf, size_t *inbytesleft,
                   char **outbuf, size_t *outbytesleft);
