dnl **************************************************************************
dnl * Initialize
dnl **************************************************************************
AC_INIT([[[llvm-deps]]],[[[0.00]]],[sdmoore@fas.harvard.edu])

dnl Identify where LLVM source tree is
LLVM_SRC_ROOT="`(cd $srcdir/../..; pwd)`"
LLVM_OBJ_ROOT="`(cd ../..; pwd)`"

dnl Tell autoconf that this is an LLVM project being configured
dnl This provides the --with-llvmsrc and --with-llvmobj options
LLVM_CONFIG_PROJECT($LLVM_SRC_ROOT,$LLVM_OBJ_ROOT)

dnl Tell autoconf that the auxilliary files are actually located in
dnl the LLVM autoconf directory, not here.
AC_CONFIG_AUX_DIR($LLVM_SRC/autoconf)

dnl Verify that the source directory is valid
AC_CONFIG_SRCDIR(["Makefile.common.in"])

dnl Configure a common Makefile
AC_CONFIG_FILES(Makefile.common)

dnl Configure project makefiles
dnl List every Makefile that exists within your source tree
AC_CONFIG_MAKEFILE(Makefile)
AC_CONFIG_MAKEFILE(lib/Makefile)
AC_CONFIG_MAKEFILE(runtime/Makefile)
AC_CONFIG_MAKEFILE(test/Makefile)

dnl **************************************************************************
dnl * Determine which system we are building on
dnl **************************************************************************

dnl **************************************************************************
dnl * Check for programs.
dnl **************************************************************************

dnl **************************************************************************
dnl * Check for libraries.
dnl **************************************************************************

dnl Check for GNU GMP
#AC_CHECK_LIB(gmp, __gmpz_init)

dnl Check for CVC3
#AC_CHECK_LIB(cvc3, vc_get_error_status,[],[],[-lgmp -lstdc++])

dnl **************************************************************************
dnl * Checks for header files.
dnl **************************************************************************

dnl **************************************************************************
dnl * Checks for typedefs, structures, and compiler characteristics.
dnl **************************************************************************

dnl **************************************************************************
dnl * Checks for library functions.
dnl **************************************************************************

dnl **************************************************************************
dnl * Enable various compile-time options
dnl **************************************************************************

dnl **************************************************************************
dnl * Set the location of various third-party software packages
dnl **************************************************************************

dnl Specify the location of the llvm-poolalloc project
AC_ARG_WITH(poolalloc-srcdir,
  AS_HELP_STRING([--with-poolalloc-srcdir],
    [Specify location of Pool Allocation source code]),
    AC_SUBST(poolallocsrcdir,"$withval"),
    AC_SUBST(poolallocsrcdir,"$LLVM_SRC_ROOT/projects/poolalloc"
    ))

AC_ARG_WITH(poolalloc-objdir,
  AS_HELP_STRING([--with-poolalloc-objdir],
    [Specify location of Pool Allocation object code]),
    AC_SUBST(poolallocobjdir,"$withval"),
    AC_SUBST(poolallocobjdir,"$LLVM_OBJ_ROOT/projects/poolalloc"
    ))

dnl Specify the location of the LLVM Test Suite
AC_ARG_WITH(test-srcdir,
  AS_HELP_STRING([--with-test-srcdir],
    [Specify location of LLVM Test Suite source code]),
    AC_SUBST(testsrcdir,"$withval"),
    AC_SUBST(testsrcdir,"$LLVM_SRC_ROOT/projects/test-suite"
    ))

AC_ARG_WITH(test-objdir,
  AS_HELP_STRING([--with-test-objdir],
    [Specify location of LLVM Test Suite object code]),
    AC_SUBST(testobjdir,"$withval"),
    AC_SUBST(testobjdir,"$LLVM_OBJ_ROOT/projects/test-suite"
    ))

dnl Ensure that all pathnames are absolute pathnames
poolallocsrcdir=`cd $poolallocsrcdir; pwd`
poolallocobjdir=`cd $poolallocobjdir; pwd`
testsrcdir=`cd $testsrcdir; pwd`
testobjdir=`cd $testobjdir; pwd`

dnl **************************************************************************
dnl * Create the output files
dnl **************************************************************************

dnl AC_CONFIG_HEADERS(include/deps/config.h)
AC_OUTPUT
