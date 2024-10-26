# Set the minimum required version of CMake to be 3.20
cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

# Create a project named "ipqp_tester"
project(
	libIPQP
	VERSION 0.16.0
	DESCRIPTION "IPQP with sample code and tests"
	LANGUAGES C
)

# Require C11 standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Enable all warnings
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

################################################################

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(liboqs 0.10.0 REQUIRED)

################################################################

# Include the directories, "include" and "source", to the search path for header files.
include_directories(
	"${PROJECT_SOURCE_DIR}/include"
)

# Define a variable named LIB_PUBLIC_HEADER_FILES that contains a list of public header files.
set(LIB_PUBLIC_HEADER_FILES
	"${PROJECT_SOURCE_DIR}/include/ipqp_common.h"
	"${PROJECT_SOURCE_DIR}/include/ipqp_device.h"
	"${PROJECT_SOURCE_DIR}/include/ipqp_apdu.h"
	"${PROJECT_SOURCE_DIR}/source/ipqp.h"
)

# Define a variable named LIB_SOURCE_FILES that contains a list of source files of this library.
set(LIB_SOURCE_FILES
	"${PROJECT_SOURCE_DIR}/source/ipqp_common.c"
	"${PROJECT_SOURCE_DIR}/source/ipqp_device.c"
	"${PROJECT_SOURCE_DIR}/source/ipqp_device_spi.c"
	"${PROJECT_SOURCE_DIR}/source/ipqp_device_uart.c"
	"${PROJECT_SOURCE_DIR}/source/ipqp_device_i2c.c"
	"${PROJECT_SOURCE_DIR}/source/ipqp_device_tcp.c"
    "${PROJECT_SOURCE_DIR}/source/ipqp_apdu.c"
	"${PROJECT_SOURCE_DIR}/source/ipqp_apdu_spi.c"
	"${PROJECT_SOURCE_DIR}/source/ipqp_apdu_uart.c"
	"${PROJECT_SOURCE_DIR}/source/ipqp_apdu_i2c.c"
	"${PROJECT_SOURCE_DIR}/source/ipqp_apdu_tcp.c"
	"${PROJECT_SOURCE_DIR}/source/ipqp.c"
)

# Add shared libraries to the project.
# The library is created by compiling the source files listed in LIB_SOURCE_FILES.
add_library(ipqp SHARED ${LIB_SOURCE_FILES})

# Set the PUBLIC_HEADER property to LIB_PUBLIC_HEADER_FILES.
# It means that the header files listed in LIB_PUBLIC_HEADER_FILES are considered the public header file for the library.
set_target_properties(
	ipqp PROPERTIES
	PUBLIC_HEADER "${LIB_PUBLIC_HEADER_FILES}"
)

################################################################

# to enable debug mode
set(DEBUG_MODE_ENABLED true)
set(DEBUG_LEVEL 0)

# get current time
execute_process (
    COMMAND bash -c "echo -n `date +\"%A %b. %d %H:%M:%S %Y\"`"
    OUTPUT_VARIABLE BUILD_TIME
)
message("BUILD_TIME: " ${BUILD_TIME})
set(BUILD_TIME "${BUILD_TIME}")
#set(BUILD_TIME "Have a nice day")
#add_definitions(-DBUILD_TIME=\"${BUILD_TIME}\")

configure_file("${PROJECT_SOURCE_DIR}/include/ipqp_proj_conf.h.in" "${PROJECT_SOURCE_DIR}/include/ipqp_proj_conf.h")

################################################################

# SPI device configuration
set(SPI_DEV_ENABLED         "true")
set(SPI_DEV_NAME            "/dev/spidev0.1")
set(SPI_MODE                "0")
set(SPI_BITS_PER_WORD       "8")
set(SPI_MAX_SPEED_HZ        "1000000")
set(SPI_BUFFER_SIZE          "2048")
set(SPI_PACKET_DATA_SIZE    "1024")

# UART device configuration
set(UART_DEV_ENABLED        "true")
set(UART_DEV_NAME           "/dev/ttyAMA0")
# set(UART_DEV_NAME           "/dev/ttyUSB0")
set(UART_OPEN_FLAGS         "(O_RDWR | O_NDELAY | O_NOCTTY)")
set(UART_INPUT_MODE_FLAGS   "(IGNPAR)")
set(UART_OUTPUT_MODE_FLAGS  "DEFAULT_UART_CONFIG")
set(UART_CONTROL_MODE_FLAGS "(B115200 | CS8 | CLOCAL | CREAD)")
set(UART_LOCAL_MODE_FLAGS   "DEFAULT_UART_CONFIG")
set(UART_BUFFER_SIZE        "2048")
set(UART_PACKET_DATA_SIZE   "1024")

# I2C device configuration
set(I2C_DEV_ENABLED         "true")
set(I2C_DEV_NAME            "/dev/i2c-0")
set(I2C_OPEN_FLAGS          "(O_RDWR)")
set(I2C_SLAVE_ADDRESS       "0x56")
set(I2C_TENBITS_ADDR        "false")
set(I2C_BUFFER_SIZE         "1536")
set(I2C_PACKET_DATA_SIZE    "512")

# TCP server configuration
set(TCP_DEV_ENABLED         "true")
set(TCP_DEV_IP              "127.0.0.1")
set(TCP_DEV_PORT            "5566")
set(TCP_TIMEOUT_SEC         "10")
set(TCP_RETRIES_ON_FAILURE  "100")
set(TCP_BUFFER_SIZE         "10240")

configure_file("${PROJECT_SOURCE_DIR}/include/ipqp_dev_conf.h.in" "${PROJECT_SOURCE_DIR}/include/ipqp_dev_conf.h")

################################################################

file(
    COPY "${PROJECT_SOURCE_DIR}/tests/loop_test.sh"
    DESTINATION "./"
    FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

add_executable(
	project_info
	"tests/project_info.c"
	"tests/test_common.c"
)
target_link_libraries(project_info PRIVATE ipqp oqs OpenSSL::Crypto)

########## TEST START #########
add_executable(
	simple_test
	"tests/simple_test.c"
	"tests/test_common.c"
)
target_link_libraries(simple_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	tcp_device_emu_h
	"tests/tcp_device_emu_h.c"
	"tests/test_common.c"
)
target_link_libraries(tcp_device_emu_h PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	tcp_device_emu_c
	"tests/tcp_device_emu_c.c"
	"tests/kat.c"
	"tests/test_common.c"
)
target_link_libraries(tcp_device_emu_c PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	uart_device_emu_h
	"tests/uart_device_emu_h.c"
	"tests/test_common.c"
)
target_link_libraries(uart_device_emu_h PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	uart_device_emu_c
	"tests/uart_device_emu_c.c"
	"tests/kat.c"
	"tests/test_common.c"
)
target_link_libraries(uart_device_emu_c PRIVATE ipqp oqs OpenSSL::Crypto)
########## TEST END #########

########## liboqs START #########
add_executable(
	liboqs_kem_genkey_test
	"tests/liboqs_kem_genkey_test.c"
	"tests/test_common.c"
)
target_link_libraries(liboqs_kem_genkey_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	liboqs_kem_encapsulate_test
	"tests/liboqs_kem_encapsulate_test.c"
	"tests/test_common.c"
)
target_link_libraries(liboqs_kem_encapsulate_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	liboqs_kem_decapsulate_test
	"tests/liboqs_kem_decapsulate_test.c"
	"tests/test_common.c"
)
target_link_libraries(liboqs_kem_decapsulate_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	liboqs_dsa_genkey_test
	"tests/liboqs_dsa_genkey_test.c"
	"tests/test_common.c"
)
target_link_libraries(liboqs_dsa_genkey_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	liboqs_dsa_sign_test
	"tests/liboqs_dsa_sign_test.c"
	"tests/test_common.c"
)
target_link_libraries(liboqs_dsa_sign_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	liboqs_dsa_verify_test
	"tests/liboqs_dsa_verify_test.c"
	"tests/test_common.c"
)
target_link_libraries(liboqs_dsa_verify_test PRIVATE ipqp oqs OpenSSL::Crypto)
########## liboqs END #########

########## SPI START #########
add_executable(
	spi_device_test
	"tests/spi_device_test.c"
	"tests/kat.c"
	"tests/test_common.c"
)
target_link_libraries(spi_device_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	spi_dsa_genkey_test
	"tests/spi_dsa_genkey_test.c"
	"tests/test_common.c"
)
target_link_libraries(spi_dsa_genkey_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	spi_dsa_sign_test
	"tests/spi_dsa_sign_test.c"
	"tests/test_common.c"
)
target_link_libraries(spi_dsa_sign_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	spi_dsa_verify_test
	"tests/spi_dsa_verify_test.c"
	"tests/test_common.c"
)
target_link_libraries(spi_dsa_verify_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	spi_dsa_full_test
	"tests/spi_dsa_full_test.c"
	"tests/test_common.c"
	"tests/kat.c"
)
target_link_libraries(spi_dsa_full_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	spi_kem_genkey_test
	"tests/spi_kem_genkey_test.c"
	"tests/test_common.c"
)
target_link_libraries(spi_kem_genkey_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	spi_kem_encapsulate_test
	"tests/spi_kem_encapsulate_test.c"
	"tests/test_common.c"
)
target_link_libraries(spi_kem_encapsulate_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	spi_kem_decapsulate_test
	"tests/spi_kem_decapsulate_test.c"
	"tests/test_common.c"
)
target_link_libraries(spi_kem_decapsulate_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	spi_kem_full_test
	"tests/spi_kem_full_test.c"
	"tests/kat.c"
	"tests/test_common.c"
)
target_link_libraries(spi_kem_full_test PRIVATE ipqp oqs OpenSSL::Crypto)
########## SPI END #########

########## UART START #########
add_executable(
	uart_device_test
	"tests/uart_device_test.c"
	"tests/kat.c"
	"tests/test_common.c"
)
target_link_libraries(uart_device_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	uart_dsa_genkey_test
	"tests/uart_dsa_genkey_test.c"
	"tests/test_common.c"
)
target_link_libraries(uart_dsa_genkey_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	uart_dsa_sign_test
	"tests/uart_dsa_sign_test.c"
	"tests/test_common.c"
)
target_link_libraries(uart_dsa_sign_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	uart_dsa_verify_test
	"tests/uart_dsa_verify_test.c"
	"tests/test_common.c"
)
target_link_libraries(uart_dsa_verify_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	uart_dsa_full_test
	"tests/uart_dsa_full_test.c"
	"tests/test_common.c"
	"tests/kat.c"
)
target_link_libraries(uart_dsa_full_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	uart_kem_genkey_test
	"tests/uart_kem_genkey_test.c"
	"tests/test_common.c"
)
target_link_libraries(uart_kem_genkey_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	uart_kem_encapsulate_test
	"tests/uart_kem_encapsulate_test.c"
	"tests/test_common.c"
)
target_link_libraries(uart_kem_encapsulate_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	uart_kem_decapsulate_test
	"tests/uart_kem_decapsulate_test.c"
	"tests/test_common.c"
)
target_link_libraries(uart_kem_decapsulate_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	uart_kem_full_test
	"tests/uart_kem_full_test.c"
	"tests/kat.c"
	"tests/test_common.c"
)
target_link_libraries(uart_kem_full_test PRIVATE ipqp oqs OpenSSL::Crypto)
########## UART END #########

########## I2C START #########
add_executable(
	i2c_device_test
	"tests/i2c_device_test.c"
	"tests/kat.c"
	"tests/test_common.c"
)
target_link_libraries(i2c_device_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	i2c_dsa_genkey_test
	"tests/i2c_dsa_genkey_test.c"
	"tests/test_common.c"
)
target_link_libraries(i2c_dsa_genkey_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	i2c_dsa_sign_test
	"tests/i2c_dsa_sign_test.c"
	"tests/test_common.c"
)
target_link_libraries(i2c_dsa_sign_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	i2c_dsa_verify_test
	"tests/i2c_dsa_verify_test.c"
	"tests/test_common.c"
)
target_link_libraries(i2c_dsa_verify_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	i2c_dsa_full_test
	"tests/i2c_dsa_full_test.c"
	"tests/test_common.c"
	"tests/kat.c"
)
target_link_libraries(i2c_dsa_full_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	i2c_kem_genkey_test
	"tests/i2c_kem_genkey_test.c"
	"tests/test_common.c"
)
target_link_libraries(i2c_kem_genkey_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	i2c_kem_encapsulate_test
	"tests/i2c_kem_encapsulate_test.c"
	"tests/test_common.c"
)
target_link_libraries(i2c_kem_encapsulate_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	i2c_kem_decapsulate_test
	"tests/i2c_kem_decapsulate_test.c"
	"tests/test_common.c"
)
target_link_libraries(i2c_kem_decapsulate_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	i2c_kem_full_test
	"tests/i2c_kem_full_test.c"
	"tests/kat.c"
	"tests/test_common.c"
)
target_link_libraries(i2c_kem_full_test PRIVATE ipqp oqs OpenSSL::Crypto)
########## I2C END #########

########## TCP START #########
add_executable(
	tcp_device_test
	"tests/tcp_device_test.c"
	"tests/kat.c"
	"tests/test_common.c"
)
target_link_libraries(tcp_device_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	tcp_dsa_genkey_test
	"tests/tcp_dsa_genkey_test.c"
	"tests/test_common.c"
)
target_link_libraries(tcp_dsa_genkey_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	tcp_dsa_sign_test
	"tests/tcp_dsa_sign_test.c"
	"tests/test_common.c"
)
target_link_libraries(tcp_dsa_sign_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	tcp_dsa_verify_test
	"tests/tcp_dsa_verify_test.c"
	"tests/test_common.c"
)
target_link_libraries(tcp_dsa_verify_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	tcp_dsa_full_test
	"tests/tcp_dsa_full_test.c"
	"tests/test_common.c"
	"tests/kat.c"
)
target_link_libraries(tcp_dsa_full_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	tcp_kem_genkey_test
	"tests/tcp_kem_genkey_test.c"
	"tests/test_common.c"
)
target_link_libraries(tcp_kem_genkey_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	tcp_kem_encapsulate_test
	"tests/tcp_kem_encapsulate_test.c"
	"tests/test_common.c"
)
target_link_libraries(tcp_kem_encapsulate_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	tcp_kem_decapsulate_test
	"tests/tcp_kem_decapsulate_test.c"
	"tests/test_common.c"
)
target_link_libraries(tcp_kem_decapsulate_test PRIVATE ipqp oqs OpenSSL::Crypto)

add_executable(
	tcp_kem_full_test
	"tests/tcp_kem_full_test.c"
	"tests/kat.c"
	"tests/test_common.c"
)
target_link_libraries(tcp_kem_full_test PRIVATE ipqp oqs OpenSSL::Crypto)
########## TCP END #########

################################################################

# Enables testing for the project.
enable_testing()

# set 
set(PASS_TEST_REGEX "PASS;SUCCESS")
set(FAIL_TEST_REGEX "FAIL;ERROR")
set(SKIP_TEST_REGEX "SKIP")

add_test(
	NAME simple_test
	COMMAND simple_test
)

set_tests_properties(
	simple_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
) 

# Show the lib infomation
add_test(
	NAME project_info
	COMMAND project_info
)

set_tests_properties(
	project_info PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

###############################

# Test KEM key-generation for Kyber 512
add_test(
	NAME liboqs_kem_genkey_kyber_512_test
	COMMAND liboqs_kem_genkey_test kyber_512
)

set_tests_properties(
	liboqs_kem_genkey_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-generation for Kyber 768
add_test(
	NAME liboqs_kem_genkey_kyber_768_test
	COMMAND liboqs_kem_genkey_test kyber_768
)

set_tests_properties(
	liboqs_kem_genkey_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-generation for Kyber 1024
add_test(
	NAME liboqs_kem_genkey_kyber_1024_test
	COMMAND liboqs_kem_genkey_test kyber_1024
)

set_tests_properties(
	liboqs_kem_genkey_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 512
add_test(
	NAME liboqs_kem_encapsulate_kyber_512_test
	COMMAND liboqs_kem_encapsulate_test kyber_512
)

set_tests_properties(
	liboqs_kem_encapsulate_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 768
add_test(
	NAME liboqs_kem_encapsulate_kyber_768_test
	COMMAND liboqs_kem_encapsulate_test kyber_768
)

set_tests_properties(
	liboqs_kem_encapsulate_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 1024
add_test(
	NAME liboqs_kem_encapsulate_kyber_1024_test
	COMMAND liboqs_kem_encapsulate_test kyber_1024
)

set_tests_properties(
	liboqs_kem_encapsulate_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 512
add_test(
	NAME liboqs_kem_decapsulate_kyber_512_test
	COMMAND liboqs_kem_decapsulate_test kyber_512
)

set_tests_properties(
	liboqs_kem_decapsulate_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 768
add_test(
	NAME liboqs_kem_decapsulate_kyber_768_test
	COMMAND liboqs_kem_decapsulate_test kyber_768
)

set_tests_properties(
	liboqs_kem_decapsulate_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 1024
add_test(
	NAME liboqs_kem_decapsulate_kyber_1024_test
	COMMAND liboqs_kem_decapsulate_test kyber_1024
)

set_tests_properties(
	liboqs_kem_decapsulate_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 2
add_test(
	NAME liboqs_dsa_genkey_dilithium_2_test
	COMMAND liboqs_dsa_genkey_test dilithium_2
)

set_tests_properties(
	liboqs_dsa_genkey_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 3
add_test(
	NAME liboqs_dsa_genkey_dilithium_3_test
	COMMAND liboqs_dsa_genkey_test dilithium_3
)

set_tests_properties(
	liboqs_dsa_genkey_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 5
add_test(
	NAME liboqs_dsa_genkey_dilithium_5_test
	COMMAND liboqs_dsa_genkey_test dilithium_5
)

set_tests_properties(
	liboqs_dsa_genkey_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 2
add_test(
	NAME liboqs_dsa_sign_dilithium_2_test
	COMMAND liboqs_dsa_sign_test dilithium_2
)

set_tests_properties(
	liboqs_dsa_sign_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 3
add_test(
	NAME liboqs_dsa_sign_dilithium_3_test
	COMMAND liboqs_dsa_sign_test dilithium_3
)

set_tests_properties(
	liboqs_dsa_sign_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 5
add_test(
	NAME liboqs_dsa_sign_dilithium_5_test
	COMMAND liboqs_dsa_sign_test dilithium_5
)

set_tests_properties(
	liboqs_dsa_sign_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 2
add_test(
	NAME liboqs_dsa_verify_dilithium_2_test
	COMMAND liboqs_dsa_verify_test dilithium_2
)

set_tests_properties(
	liboqs_dsa_verify_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 3
add_test(
	NAME liboqs_dsa_verify_dilithium_3_test
	COMMAND liboqs_dsa_verify_test dilithium_3
)

set_tests_properties(
	liboqs_dsa_verify_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 5
add_test(
	NAME liboqs_dsa_verify_dilithium_5_test
	COMMAND liboqs_dsa_verify_test dilithium_5
)

set_tests_properties(
	liboqs_dsa_verify_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

###############################

# Test KEM key-generation for Kyber 512
add_test(
	NAME spi_kem_genkey_kyber_512_test
	COMMAND spi_kem_genkey_test kyber_512
)

set_tests_properties(
	spi_kem_genkey_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-generation for Kyber 768
add_test(
	NAME spi_kem_genkey_kyber_768_test
	COMMAND spi_kem_genkey_test kyber_768
)

set_tests_properties(
	spi_kem_genkey_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-generation for Kyber 1024
add_test(
	NAME spi_kem_genkey_kyber_1024_test
	COMMAND spi_kem_genkey_test kyber_1024
)

set_tests_properties(
	spi_kem_genkey_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 512
add_test(
	NAME spi_kem_encapsulate_kyber_512_test
	COMMAND spi_kem_encapsulate_test kyber_512
)

set_tests_properties(
	spi_kem_encapsulate_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 768
add_test(
	NAME spi_kem_encapsulate_kyber_768_test
	COMMAND spi_kem_encapsulate_test kyber_768
)

set_tests_properties(
	spi_kem_encapsulate_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 1024
add_test(
	NAME spi_kem_encapsulate_kyber_1024_test
	COMMAND spi_kem_encapsulate_test kyber_1024
)

set_tests_properties(
	spi_kem_encapsulate_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 512
add_test(
	NAME spi_kem_decapsulate_kyber_512_test
	COMMAND spi_kem_decapsulate_test kyber_512
)

set_tests_properties(
	spi_kem_decapsulate_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 768
add_test(
	NAME spi_kem_decapsulate_kyber_768_test
	COMMAND spi_kem_decapsulate_test kyber_768
)

set_tests_properties(
	spi_kem_decapsulate_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 1024
add_test(
	NAME spi_kem_decapsulate_kyber_1024_test
	COMMAND spi_kem_decapsulate_test kyber_1024
)

set_tests_properties(
	spi_kem_decapsulate_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 2
add_test(
	NAME spi_dsa_genkey_dilithium_2_test
	COMMAND spi_dsa_genkey_test dilithium_2
)

set_tests_properties(
	spi_dsa_genkey_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 3
add_test(
	NAME spi_dsa_genkey_dilithium_3_test
	COMMAND spi_dsa_genkey_test dilithium_3
)

set_tests_properties(
	spi_dsa_genkey_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 5
add_test(
	NAME spi_dsa_genkey_dilithium_5_test
	COMMAND spi_dsa_genkey_test dilithium_5
)

set_tests_properties(
	spi_dsa_genkey_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 2
add_test(
	NAME spi_dsa_sign_dilithium_2_test
	COMMAND spi_dsa_sign_test dilithium_2
)

set_tests_properties(
	spi_dsa_sign_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 3
add_test(
	NAME spi_dsa_sign_dilithium_3_test
	COMMAND spi_dsa_sign_test dilithium_3
)

set_tests_properties(
	spi_dsa_sign_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 5
add_test(
	NAME spi_dsa_sign_dilithium_5_test
	COMMAND spi_dsa_sign_test dilithium_5
)

set_tests_properties(
	spi_dsa_sign_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 2
add_test(
	NAME spi_dsa_verify_dilithium_2_test
	COMMAND spi_dsa_verify_test dilithium_2
)

set_tests_properties(
	spi_dsa_verify_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 3
add_test(
	NAME spi_dsa_verify_dilithium_3_test
	COMMAND spi_dsa_verify_test dilithium_3
)

set_tests_properties(
	spi_dsa_verify_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 5
add_test(
	NAME spi_dsa_verify_dilithium_5_test
	COMMAND spi_dsa_verify_test dilithium_5
)

set_tests_properties(
	spi_dsa_verify_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

###############################

# Test KEM key-generation for Kyber 512
add_test(
	NAME uart_kem_genkey_kyber_512_test
	COMMAND uart_kem_genkey_test kyber_512
)

set_tests_properties(
	uart_kem_genkey_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-generation for Kyber 768
add_test(
	NAME uart_kem_genkey_kyber_768_test
	COMMAND uart_kem_genkey_test kyber_768
)

set_tests_properties(
	uart_kem_genkey_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-generation for Kyber 1024
add_test(
	NAME uart_kem_genkey_kyber_1024_test
	COMMAND uart_kem_genkey_test kyber_1024
)

set_tests_properties(
	uart_kem_genkey_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 512
add_test(
	NAME uart_kem_encapsulate_kyber_512_test
	COMMAND uart_kem_encapsulate_test kyber_512
)

set_tests_properties(
	uart_kem_encapsulate_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 768
add_test(
	NAME uart_kem_encapsulate_kyber_768_test
	COMMAND uart_kem_encapsulate_test kyber_768
)

set_tests_properties(
	uart_kem_encapsulate_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 1024
add_test(
	NAME uart_kem_encapsulate_kyber_1024_test
	COMMAND uart_kem_encapsulate_test kyber_1024
)

set_tests_properties(
	uart_kem_encapsulate_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 512
add_test(
	NAME uart_kem_decapsulate_kyber_512_test
	COMMAND uart_kem_decapsulate_test kyber_512
)

set_tests_properties(
	uart_kem_decapsulate_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 768
add_test(
	NAME uart_kem_decapsulate_kyber_768_test
	COMMAND uart_kem_decapsulate_test kyber_768
)

set_tests_properties(
	uart_kem_decapsulate_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 1024
add_test(
	NAME uart_kem_decapsulate_kyber_1024_test
	COMMAND uart_kem_decapsulate_test kyber_1024
)

set_tests_properties(
	uart_kem_decapsulate_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 2
add_test(
	NAME uart_dsa_genkey_dilithium_2_test
	COMMAND uart_dsa_genkey_test dilithium_2
)

set_tests_properties(
	uart_dsa_genkey_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 3
add_test(
	NAME uart_dsa_genkey_dilithium_3_test
	COMMAND uart_dsa_genkey_test dilithium_3
)

set_tests_properties(
	uart_dsa_genkey_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 5
add_test(
	NAME uart_dsa_genkey_dilithium_5_test
	COMMAND uart_dsa_genkey_test dilithium_5
)

set_tests_properties(
	uart_dsa_genkey_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 2
add_test(
	NAME uart_dsa_sign_dilithium_2_test
	COMMAND uart_dsa_sign_test dilithium_2
)

set_tests_properties(
	uart_dsa_sign_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 3
add_test(
	NAME uart_dsa_sign_dilithium_3_test
	COMMAND uart_dsa_sign_test dilithium_3
)

set_tests_properties(
	uart_dsa_sign_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 5
add_test(
	NAME uart_dsa_sign_dilithium_5_test
	COMMAND uart_dsa_sign_test dilithium_5
)

set_tests_properties(
	uart_dsa_sign_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 2
add_test(
	NAME uart_dsa_verify_dilithium_2_test
	COMMAND uart_dsa_verify_test dilithium_2
)

set_tests_properties(
	uart_dsa_verify_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 3
add_test(
	NAME uart_dsa_verify_dilithium_3_test
	COMMAND uart_dsa_verify_test dilithium_3
)

set_tests_properties(
	uart_dsa_verify_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 5
add_test(
	NAME uart_dsa_verify_dilithium_5_test
	COMMAND uart_dsa_verify_test dilithium_5
)

set_tests_properties(
	uart_dsa_verify_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

###############################

# Test KEM key-generation for Kyber 512
add_test(
	NAME i2c_kem_genkey_kyber_512_test
	COMMAND i2c_kem_genkey_test kyber_512
)

set_tests_properties(
	i2c_kem_genkey_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-generation for Kyber 768
add_test(
	NAME i2c_kem_genkey_kyber_768_test
	COMMAND i2c_kem_genkey_test kyber_768
)

set_tests_properties(
	i2c_kem_genkey_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-generation for Kyber 1024
add_test(
	NAME i2c_kem_genkey_kyber_1024_test
	COMMAND i2c_kem_genkey_test kyber_1024
)

set_tests_properties(
	i2c_kem_genkey_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 512
add_test(
	NAME i2c_kem_encapsulate_kyber_512_test
	COMMAND i2c_kem_encapsulate_test kyber_512
)

set_tests_properties(
	i2c_kem_encapsulate_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 768
add_test(
	NAME i2c_kem_encapsulate_kyber_768_test
	COMMAND i2c_kem_encapsulate_test kyber_768
)

set_tests_properties(
	i2c_kem_encapsulate_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 1024
add_test(
	NAME i2c_kem_encapsulate_kyber_1024_test
	COMMAND i2c_kem_encapsulate_test kyber_1024
)

set_tests_properties(
	i2c_kem_encapsulate_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 512
add_test(
	NAME i2c_kem_decapsulate_kyber_512_test
	COMMAND i2c_kem_decapsulate_test kyber_512
)

set_tests_properties(
	i2c_kem_decapsulate_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 768
add_test(
	NAME i2c_kem_decapsulate_kyber_768_test
	COMMAND i2c_kem_decapsulate_test kyber_768
)

set_tests_properties(
	i2c_kem_decapsulate_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 1024
add_test(
	NAME i2c_kem_decapsulate_kyber_1024_test
	COMMAND i2c_kem_decapsulate_test kyber_1024
)

set_tests_properties(
	i2c_kem_decapsulate_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 2
add_test(
	NAME i2c_dsa_genkey_dilithium_2_test
	COMMAND i2c_dsa_genkey_test dilithium_2
)

set_tests_properties(
	i2c_dsa_genkey_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 3
add_test(
	NAME i2c_dsa_genkey_dilithium_3_test
	COMMAND i2c_dsa_genkey_test dilithium_3
)

set_tests_properties(
	i2c_dsa_genkey_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 5
add_test(
	NAME i2c_dsa_genkey_dilithium_5_test
	COMMAND i2c_dsa_genkey_test dilithium_5
)

set_tests_properties(
	i2c_dsa_genkey_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 2
add_test(
	NAME i2c_dsa_sign_dilithium_2_test
	COMMAND i2c_dsa_sign_test dilithium_2
)

set_tests_properties(
	i2c_dsa_sign_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 3
add_test(
	NAME i2c_dsa_sign_dilithium_3_test
	COMMAND i2c_dsa_sign_test dilithium_3
)

set_tests_properties(
	i2c_dsa_sign_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 5
add_test(
	NAME i2c_dsa_sign_dilithium_5_test
	COMMAND i2c_dsa_sign_test dilithium_5
)

set_tests_properties(
	i2c_dsa_sign_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 2
add_test(
	NAME i2c_dsa_verify_dilithium_2_test
	COMMAND i2c_dsa_verify_test dilithium_2
)

set_tests_properties(
	i2c_dsa_verify_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 3
add_test(
	NAME i2c_dsa_verify_dilithium_3_test
	COMMAND i2c_dsa_verify_test dilithium_3
)

set_tests_properties(
	i2c_dsa_verify_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 5
add_test(
	NAME i2c_dsa_verify_dilithium_5_test
	COMMAND i2c_dsa_verify_test dilithium_5
)

set_tests_properties(
	i2c_dsa_verify_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

###############################

# Test KEM key-generation for Kyber 512
add_test(
	NAME tcp_kem_genkey_kyber_512_test
	COMMAND tcp_kem_genkey_test kyber_512
)

set_tests_properties(
	tcp_kem_genkey_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-generation for Kyber 768
add_test(
	NAME tcp_kem_genkey_kyber_768_test
	COMMAND tcp_kem_genkey_test kyber_768
)

set_tests_properties(
	tcp_kem_genkey_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-generation for Kyber 1024
add_test(
	NAME tcp_kem_genkey_kyber_1024_test
	COMMAND tcp_kem_genkey_test kyber_1024
)

set_tests_properties(
	tcp_kem_genkey_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 512
add_test(
	NAME tcp_kem_encapsulate_kyber_512_test
	COMMAND tcp_kem_encapsulate_test kyber_512
)

set_tests_properties(
	tcp_kem_encapsulate_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 768
add_test(
	NAME tcp_kem_encapsulate_kyber_768_test
	COMMAND tcp_kem_encapsulate_test kyber_768
)

set_tests_properties(
	tcp_kem_encapsulate_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-encapsulation for Kyber 1024
add_test(
	NAME tcp_kem_encapsulate_kyber_1024_test
	COMMAND tcp_kem_encapsulate_test kyber_1024
)

set_tests_properties(
	tcp_kem_encapsulate_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 512
add_test(
	NAME tcp_kem_decapsulate_kyber_512_test
	COMMAND tcp_kem_decapsulate_test kyber_512
)

set_tests_properties(
	tcp_kem_decapsulate_kyber_512_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 768
add_test(
	NAME tcp_kem_decapsulate_kyber_768_test
	COMMAND tcp_kem_decapsulate_test kyber_768
)

set_tests_properties(
	tcp_kem_decapsulate_kyber_768_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test KEM key-decapsulation for Kyber 1024
add_test(
	NAME tcp_kem_decapsulate_kyber_1024_test
	COMMAND tcp_kem_decapsulate_test kyber_1024
)

set_tests_properties(
	tcp_kem_decapsulate_kyber_1024_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 2
add_test(
	NAME tcp_dsa_genkey_dilithium_2_test
	COMMAND tcp_dsa_genkey_test dilithium_2
)

set_tests_properties(
	tcp_dsa_genkey_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 3
add_test(
	NAME tcp_dsa_genkey_dilithium_3_test
	COMMAND tcp_dsa_genkey_test dilithium_3
)

set_tests_properties(
	tcp_dsa_genkey_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA key-generation for Dilithium 5
add_test(
	NAME tcp_dsa_genkey_dilithium_5_test
	COMMAND tcp_dsa_genkey_test dilithium_5
)

set_tests_properties(
	tcp_dsa_genkey_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 2
add_test(
	NAME tcp_dsa_sign_dilithium_2_test
	COMMAND tcp_dsa_sign_test dilithium_2
)

set_tests_properties(
	tcp_dsa_sign_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 3
add_test(
	NAME tcp_dsa_sign_dilithium_3_test
	COMMAND tcp_dsa_sign_test dilithium_3
)

set_tests_properties(
	tcp_dsa_sign_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA singing for Dilithium 5
add_test(
	NAME tcp_dsa_sign_dilithium_5_test
	COMMAND tcp_dsa_sign_test dilithium_5
)

set_tests_properties(
	tcp_dsa_sign_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 2
add_test(
	NAME tcp_dsa_verify_dilithium_2_test
	COMMAND tcp_dsa_verify_test dilithium_2
)

set_tests_properties(
	tcp_dsa_verify_dilithium_2_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 3
add_test(
	NAME tcp_dsa_verify_dilithium_3_test
	COMMAND tcp_dsa_verify_test dilithium_3
)

set_tests_properties(
	tcp_dsa_verify_dilithium_3_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)

# Test DSA verification for Dilithium 5
add_test(
	NAME tcp_dsa_verify_dilithium_5_test
	COMMAND tcp_dsa_verify_test dilithium_5
)

set_tests_properties(
	tcp_dsa_verify_dilithium_5_test PROPERTIES
	PASS_REGULAR_EXPRESSION "${PASS_TEST_REGEX}"
	FAIL_REGULAR_EXPRESSION "${FAIL_TEST_REGEX}"
	SKIP_REGULAR_EXPRESSION "${SKIP_TEST_REGEX}"
)
