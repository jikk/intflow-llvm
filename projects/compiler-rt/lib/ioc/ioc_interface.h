//===-- ioc_interface.h -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Interface for Integer Overflow Checker (IOC)
//
//===----------------------------------------------------------------------===//

#ifndef _IOC_INTERFACE_H_
#define _IOC_INTERFACE_H_

// For now, only support linux.
// Other platforms should be easy to add,
// and probably work as-is.
#if !defined(__linux__)
//#error "IOC not supported for this platform!"
#endif

#include <stdint.h>


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


void __ioc_report_add_overflow(uint32_t line, uint32_t column,
                               const char *filename, const char *expstr,
                               uint64_t lval, uint64_t rval, uint8_t Type);
void __ioc_report_sub_overflow(uint32_t line, uint32_t column,
                               const char *filename, const char *expstr,
                               uint64_t lval, uint64_t rval, uint8_t Type);
void __ioc_report_mul_overflow(uint32_t line, uint32_t column,
                               const char *filename, const char *expstr,
                               uint64_t lval, uint64_t rval, uint8_t Type);
void __ioc_report_div_error(uint32_t line, uint32_t column,
                            const char *filename, const char *expstr,
                            uint64_t lval, uint64_t rval, uint8_t Type);
void __ioc_report_rem_error(uint32_t line, uint32_t column,
                            const char *filename, const char *expstr,
                            uint64_t lval, uint64_t rval, uint8_t Type);
void __ioc_report_shl_bitwidth(uint32_t line, uint32_t column,
                               const char *filename, const char *expstr,
                               uint64_t lval, uint64_t rval, uint8_t Type);
void __ioc_report_shr_bitwidth(uint32_t line, uint32_t column,
                               const char *filename, const char *expstr,
                               uint64_t lval, uint64_t rval, uint8_t Type);
void __ioc_report_shl_strict(uint32_t line, uint32_t column,
                             const char *filename, const char *expstr,
                             uint64_t lval, uint64_t rval, uint8_t Type);
void __ioc_report_conversion(uint32_t line, uint32_t column,
                             const char *filename,
                             const char *srcty, const char *canonsrcty,
                             const char *dstty, const char *canondstty,
                             uint64_t src, uint8_t is_signed);


#endif // _IOC_INTERFACE_H_
