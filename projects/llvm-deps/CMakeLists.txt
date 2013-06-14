cmake_minimum_required(VERSION 2.8)
set(LLVM_DIR /Users/jikk/int-llvm/cmake/modules/)
find_package(LLVM)

include_directories(include)
add_subdirectory(lib)
