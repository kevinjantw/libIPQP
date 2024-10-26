#ifndef __IPQP_COMMON_H__
#define __IPQP_COMMON_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <stddef.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <termios.h>

#include "ipqp.h"

#ifndef PRINT_SIZE_FMT
#if UINTPTR_MAX == 0xFFFFFFFF
/* 32-bit system */
#define PRINT_SIZE_FMT "%u"
#define PRINT_SSIZE_FMT "%d"
#else
/* 64-bit system */
#define PRINT_SIZE_FMT "%lu"
#define PRINT_SSIZE_FMT "%ld"
#endif
#endif

// include ipqp_proj_conf.h if the file exists
#if __has_include("ipqp_proj_conf.h")
#include "ipqp_proj_conf.h"
#endif

#ifndef IPQP_PROJECT_CONFIGURATION
#define DEBUG_MODE true
#define BUILD_TIME "DEFAULT_BUILD_TIME"
#define PROJECT_NAME "DEFAULT_PROJECT_NAME"
#define PROJECT_VER "1.2.3"
#define PROJECT_VER_MAJOR 1
#define PROJECT_VER_MINOR 2
#define PTOJECT_VER_PATCH 3
#endif

#if (DEBUG_MODE)
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT_ARR(...) print_arr(__VA_ARGS__)
#define IPQP_EC_LOG(...) ipqp_error_code_log(__VA_ARGS__)

#else
#define PRINTF(...)
#define PRINT_ARR(...)
#define IPQP_EC_LOG(...)
#endif

/**
 * @brief Prints an array of bytes in hexadecimal format.
 *
 * This function prints the elements of an array of bytes in hexadecimal format,
 * with an optional array name printed at the beginning. The output is formatted
 * with a specified number of bytes per line.
 *
 * @param arr Pointer to the array of bytes to be printed.
 * @param arr_len Length of the array.
 * @param byte_per_line Number of bytes to print per line.
 * @param arr_name Optional name of the array to be printed at the beginning.
 *
 * @return void
 */
void print_arr(uint8_t *arr, size_t arr_len, size_t byte_per_line, const char *arr_name);

/**
 * @brief Logs an error code and associated log message.
 *
 * This function logs an error code and an associated log message. The error code
 * and log message are typically used for debugging purposes. The function can be
 * customized to handle different error codes and log messages as needed.
 *
 * @param ec The error code to be logged. This should be an enum or a defined
 *           error code type.
 * @param log A pointer to a character array containing the log message. The log
 *            message should be null-terminated.
 *
 * @return void
 *
 * @note This function can be customized to handle different error codes and log
 *       messages as needed.
 */
void ipqp_error_code_log(IPQP_ErrorCode ec, char *log);

#endif /* __IPQP_COMMON_H__ */
