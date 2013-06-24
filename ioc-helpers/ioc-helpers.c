#include "ioc-helpers.h"

div_t   __ioc_div(int numerator, int denominator) {
#ifdef __OUTPUT_XML__
  if (denominator == 0) {
    const char* msg = "div: divsion-by-zero";
    char log[256];
    sprintf(log, "div: lval %d, rval %d", numerator, denominator);
    
    outputXML((char*) msg, (char*) "", 0, 0, log);
    exit(-1);
  }
#else

#endif
  return div(numerator, numerator);
}

ldiv_t  __ioc_ldiv(int numerator, int denominator) {
#ifdef __OUTPUT_XML__
  if (denominator == 0) {
    const char* msg = "ldiv: divsion-by-zero";
    char log[256];
    sprintf(log, "ldiv: lval %d, rval %d", numerator, denominator);
    
    outputXML((char*) msg, (char*) "", 0, 0, log);
    exit(-1);
  }
#else

#endif
  return ldiv(numerator, numerator);
}

lldiv_t __ioc_lldiv(int numerator, int denominator) {
#ifdef __OUTPUT_XML__
  if (denominator == 0) {
    const char* msg = "lldiv: divsion-by-zero";
    char log[256];
    sprintf(log, "lldiv: lval %d, rval %d", numerator, denominator);
    
    outputXML((char*) msg, (char*) "", 0, 0, log);
    exit(-1);
  }
#else

#endif
  return lldiv(numerator, numerator);
}

size_t __ioc_iconv(iconv_t cd,
                   char **inbuf, size_t *inbytesleft,
                   char **outbuf, size_t *outbytesleft) {
#ifdef __OUTPUT_XML__
  
#else
#endif
  return iconv(cd, inbuf, inbytesleft, outbuf, outbytesleft);
}
