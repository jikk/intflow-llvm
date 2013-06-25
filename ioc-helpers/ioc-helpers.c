#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "ioc-helpers.h"

#define __OUTPUT_XML__

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

int outputXML(char* log,
              char* fname,
              uint32_t line,
              uint32_t col,
              char* valStr) {

  const char *entry_id = NULL;
  const char *tc  = NULL;
  const char *impact = NULL;

  entry_id = getenv("ENTRY_ID");
  if (entry_id == NULL)
    entry_id = (char *) "EID_NEEDED";

  tc = getenv("TESTCASE");
  if (tc == NULL)
    tc = (char *) "TESTCASE_NEEDED";

  impact = getenv("IMPACT");
  if (impact == NULL)
    impact = (char *) "IMPACT_NEEDED";

  FILE *fp = fopen(FNAME, "w");
  if (!fp) {
    //perror("Error opening file:");
    return 0;
  }
  fprintf(fp, XML_MSG, entry_id, tc, impact, tc, log,
          fname, line, col, valStr);
  fclose(fp);
  return 1;
}
