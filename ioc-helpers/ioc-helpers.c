#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "ioc-helpers.h"
#include <stdio.h>

#define __OUTPUT_XML__

#define __OUTPUT_XML__

char* parseFName(char* fname) {

  char* s;
  int i;

 if (!fname)
	  return NULL;

  for (i = strlen(fname), s = fname; i ; i--) {
    if (fname[i] == '/') {
      s = &fname[i];
      s++;
      break;
    }
  }
  return s;
}

//Returns 1 if the triple ('name', 'line', 'col') exists in file 'file'
//Ignores 'line' and 'col' if both are 0
int existsInExclude(char *file, char *name, uint32_t line, uint32_t col) {

  char line_buffer[BUFSIZ];
  char fname[BUFSIZ];
  uint32_t fline, fcol;
  uint8_t ignores_lines;
  FILE *fd;
  int i;

  fd = fopen(file, "r");
  if (!fd) {
    perror("Error opening file:");
    return 0;
  }

  //if 0 0 is passed ignore line and col
  ignores_lines = !(line || col);
  if (ignores_lines) {
    while (fgets(line_buffer, sizeof(line_buffer), fd)) {
      sscanf(line_buffer, "%s", fname);
      if (strcmp(parseFName(name), fname) == 0){
	fclose(fd);
        return 1;
      }
    }
  } else {
    while (fgets(line_buffer, sizeof(line_buffer), fd)) {
      sscanf(line_buffer, "%s %d %d", fname, &fline, &fcol);
      if (strcmp(parseFName(name), fname) == 0 && fline == line && fcol == col){
	fclose(fd);
        return 1;
      }
    }
  }

  fclose(fd);

  return 0;
}

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

/*  if (strcmp(parseFName(fname), "HTInet.c") == 0) {
      return 1;
  }
*/

  if (strcmp(parseFName(fname), "dfa.c") == 0) {
      return 1;
  }

  //regexec line 1082 col 57
  if (strcmp(parseFName(fname), "regexec.c") == 0) {
      return 1;
  }

  if (strcmp(parseFName(fname), "dfa.c") == 0) {
      return 1;
  }
 
//check if exclude this file from our rule set
  if (fname && existsInExclude(EXCLUDE_FNAME, fname, line, col))
	  return 1;

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
    perror("Error opening file:");
    return 0;
  }
  fprintf(fp, XML_MSG, entry_id, tc, impact, tc, log,
          fname, line, col, valStr);
  fclose(fp);
  exit(-1);
  return 1;
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
