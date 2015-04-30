cmake_minimum_required(VERSION 3.1)
project(morecbitpay)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
include_directories(/Users/paul/ClionProjects/morecbitpay/include)
link_directories(/Users/paul/ClionProjects/morecbitpay)

set(SOURCE_FILES main.c)
add_executable(morecbitpay ${SOURCE_FILES} main.c bitpay.h key_utils.c)