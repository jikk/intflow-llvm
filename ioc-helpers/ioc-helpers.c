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
void __ioc___ioc_report_add_overflow(uint32_t line, uint32_t column,
                               const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T)
{
#ifdef __OUTPUT_XML__

#else
#endif

}
void __ioc___ioc_report_sub_overflow(uint32_t line, uint32_t column,
                               const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T)
{
#ifdef __OUTPUT_XML__

#else
#endif

}
void __ioc___ioc_report_mul_overflow(uint32_t line, uint32_t column,
                               const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T)
{
#ifdef __OUTPUT_XML__

#else
#endif

}
void __ioc___ioc_report_div_error(uint32_t line, uint32_t column,
                            const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T)
{
#ifdef __OUTPUT_XML__

#else
#endif

}
void __ioc___ioc_report_rem_error(uint32_t line, uint32_t column,
                            const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T)
{
#ifdef __OUTPUT_XML__

#else
#endif

}
void __ioc___ioc_report_shl_bitwidth(uint32_t line, uint32_t column,
                               const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T)
{
#ifdef __OUTPUT_XML__

#else
#endif

}
void __ioc___ioc_report_shr_bitwidth(uint32_t line, uint32_t column,
                               const char *filename, const char *exprstr,
                               uint64_t lval, uint64_t rval, uint8_t T)
{
#ifdef __OUTPUT_XML__

#else
#endif

}
void __ioc___ioc_report_shl_strict(uint32_t line, uint32_t column,
                            const char *filename, const char *exprstr,
                             uint64_t lval, uint64_t rval, uint8_t T)
{
#ifdef __OUTPUT_XML__

#else
#endif

}
void __ioc___ioc_report_conversion(uint32_t line, uint32_t column,
                             const char *filename,
                             const char *srcty, const char *canonsrcty,
                             const char *dstty, const char *canondstty,
                             uint64_t src, uint8_t S)
{
#ifdef __OUTPUT_XML__

#else
#endif
}
