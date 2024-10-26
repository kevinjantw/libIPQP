#ifndef __TEST_COMMON_H__
#define __TEST_COMMON_H__

#include "ipqp_common.h"
#include "ipqp_apdu.h"
#include "ipqp_device.h"
#include "ipqp.h"

#include <oqs/oqs.h>

#define SKIP_n_EXIT     \
    printf("SKIP\r\n"); \
    return EXIT_SUCCESS;

#define PASS_n_EXIT     \
    printf("PASS\r\n"); \
    return EXIT_SUCCESS;

#define FAIL_n_EXIT     \
    printf("FAIL\r\n"); \
    return EXIT_SUCCESS;

#endif // __TEST_COMMON_H__
