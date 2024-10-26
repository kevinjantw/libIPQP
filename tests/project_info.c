#include "ipqp_common.h"
#include "ipqp_device.h"
#include "test_common.h"

// based on macros in https://sourceforge.net/p/predef/wiki/Compilers/
static void print_compiler_info(void)
{
#if defined(__clang__)
	printf("Compiler:         clang (%s)\n", __clang_version__);
#elif defined(__GNUC_PATCHLEVEL__)
	printf("Compiler:         gcc (%d.%d.%d) __STDC_VERSION__(%lu)\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__, __STDC_VERSION__);
#elif defined(__GNUC_MINOR__)
	printf("Compiler:         gcc (%d.%d)\n", __GNUC__, __GNUC_MINOR__);
#elif defined(__INTEL_COMPILER)
	printf("Compiler:         Intel C/C++ (%d)\n", __INTEL_COMPILER);
#elif defined(_MSC_FULL_VER)
	printf("Compiler:         Microsoft C/C++ (%d)\n", _MSC_FULL_VER);
#else
	printf("Compiler:         Unknown"\n);
#endif
#if defined(OQS_COMPILE_OPTIONS)
	printf("Compile options:  %s\n", OQS_COMPILE_OPTIONS);
#endif
}

// based on macros in https://sourceforge.net/p/predef/wiki/Architectures/
static void print_platform_info(void)
{
#if defined(OQS_COMPILE_BUILD_TARGET)
	printf("Target platform:  %s", OQS_COMPILE_BUILD_TARGET);
#elif defined(_WIN64)
	printf("Target platform:  Windows (64-bit)");
#elif defined(_WIN32)
	printf("Target platform:  Windows (32-bit)");
#else
	printf("Target platform:  Unknown");
#endif
#if defined(OQS_SPEED_USE_ARM_PMU)
	printf(" - ARM PMU options enabled");
#endif
	printf("\n");
}

#if defined(OQS_USE_OPENSSL)
#include <openssl/opensslv.h>
#endif

#if defined(OQS_DIST_X86_64_BUILD)
#define AES_C_OR_NI_OR_ARM(stmt_c, stmt_ni, stmt_arm) \
	do                                                \
	{                                                 \
		if (OQS_CPU_has_extension(OQS_CPU_EXT_AES))   \
		{                                             \
			stmt_ni;                                  \
		}                                             \
		else                                          \
		{                                             \
			stmt_c;                                   \
		}                                             \
	} while (0)
#elif defined(OQS_DIST_ARM64_V8_BUILD)
#define AES_C_OR_NI_OR_ARM(stmt_c, stmt_ni, stmt_arm)   \
	do                                                  \
	{                                                   \
		if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_AES)) \
		{                                               \
			stmt_arm;                                   \
		}                                               \
		else                                            \
		{                                               \
			stmt_c;                                     \
		}                                               \
	} while (0)
#elif defined(OQS_USE_AES_INSTRUCTIONS)
#define AES_C_OR_NI_OR_ARM(stmt_c, stmt_ni, stmt_arm) \
	stmt_ni
#elif defined(OQS_USE_ARM_AES_INSTRUCTIONS)
#define AES_C_OR_NI_OR_ARM(stmt_c, stmt_ni, stmt_arm) \
	stmt_arm
#else
#define AES_C_OR_NI_OR_ARM(stmt_c, stmt_ni, stmt_arm) \
	stmt_c
#endif

#if defined(OQS_DIST_ARM64_V8_BUILD)
#define SHA2_C_OR_ARM(stmt_c, stmt_arm)                  \
	do                                                   \
	{                                                    \
		if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_SHA2)) \
		{                                                \
			stmt_arm;                                    \
		}                                                \
		else                                             \
		{                                                \
			stmt_c;                                      \
		}                                                \
	} while (0)
#elif defined(OQS_USE_ARM_SHA2_INSTRUCTIONS)
#define SHA2_C_OR_ARM(stmt_c, stmt_arm) \
	stmt_arm
#else
#define SHA2_C_OR_ARM(stmt_c, stmt_arm) \
	stmt_c
#endif

/* Display all active CPU extensions: */
static void print_cpu_extensions(void)
{
#if defined(OQS_DIST_BUILD)
	printf("CPU exts active: ");
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ADX))
	{
		printf(" ADX");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AES))
	{
		printf(" AES");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX))
	{
		printf(" AVX");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2))
	{
		printf(" AVX2");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX512))
	{
		printf(" AVX512");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_BMI1))
	{
		printf(" BMI1");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_BMI2))
	{
		printf(" BMI2");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_PCLMULQDQ))
	{
		printf(" PCLMULQDQ");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_VPCLMULQDQ))
	{
		printf(" VPCLMULQDQ");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT))
	{
		printf(" POPCNT");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_SSE))
	{
		printf(" SSE");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_SSE2))
	{
		printf(" SSE2");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_SSE3))
	{
		printf(" SSE3");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_AES))
	{
		printf(" AES");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_SHA2))
	{
		printf(" SHA2");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_SHA3))
	{
		printf(" SHA3");
	}
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON))
	{
		printf(" NEON");
	}
#else
	printf("CPU exts compile-time: ");
#ifdef OQS_USE_ADX_INSTRUCTIONS
	printf(" ADX");
#endif
#ifdef OQS_USE_AES_INSTRUCTIONS
	printf(" AES");
#endif
#ifdef OQS_USE_AVX_INSTRUCTIONS
	printf(" AVX");
#endif
#ifdef OQS_USE_AVX2_INSTRUCTIONS
	printf(" AVX2");
#endif
#ifdef OQS_USE_AVX512_INSTRUCTIONS
	printf(" AVX512");
#endif
#ifdef OQS_USE_BMI1_INSTRUCTIONS
	printf(" BMI1");
#endif
#ifdef OQS_USE_BMI2_INSTRUCTIONS
	printf(" BMI2");
#endif
#ifdef OQS_USE_PCLMULQDQ_INSTRUCTIONS
	printf(" PCLMULQDQ");
#endif
#ifdef OQS_USE_POPCNT_INSTRUCTIONS
	printf(" POPCNT");
#endif
#ifdef OQS_USE_SSE_INSTRUCTIONS
	printf(" SSE");
#endif
#ifdef OQS_USE_SSE2_INSTRUCTIONS
	printf(" SSE2");
#endif
#ifdef OQS_USE_SSE3_INSTRUCTIONS
	printf(" SSE3");
#endif
#ifdef OQS_USE_ARM_AES_INSTRUCTIONS
	printf(" AES");
#endif
#ifdef OQS_USE_ARM_SHA2_INSTRUCTIONS
	printf(" SHA2");
#endif
#ifdef OQS_USE_ARM_SHA3_INSTRUCTIONS
	printf(" SHA3");
#endif
#ifdef OQS_USE_ARM_NEON_INSTRUCTIONS
	printf(" NEON");
#endif
	printf("\n");
#endif
}

static void print_oqs_configuration(void)
{
	/* Display all options as per https://github.com/open-quantum-safe/liboqs/wiki/Customizing-liboqs:
	 * BUILD_SHARED_LIBS: Performance relevance small/improbable
	 * CMAKE_BUILD_TYPE: If Debug, -g compiler option will be shown;
	 *                   -O3 for Release build
	 * CMAKE_INSTALL_PREFIX: Not performance relevant
	 * OQS_ENABLE_KEM|SIG: alg absence/presence detected on run; can be output
	 *                     by not passing an alg name to the test programs
	 * OQS_BUILD_ONLY_LIB: Not performance relevant
	 * OQS_DIST_BUILD: Set if output "CPU exts active" present;
	 *                 otherwise, "CPU exts compile-time:" output
	 * OQS_USE_OPENSSL: Explicitly output
	 * OQS_OPT_TARGET: Visible by looking at compile options (-march or -mcpu):
	 *                 'auto' -> "-march|cpu=native"
	 * OQS_SPEED_USE_ARM_PMU: Output with Target platform
	 * USE_SANITIZER: -fsanitize= option present in compile options
	 * OQS_ENABLE_TEST_CONSTANT_TIME: only shown below
	 */
	printf("OQS version:      %s\n", OQS_VERSION_TEXT);
#if defined(OQS_COMPILE_GIT_COMMIT)
	printf("Git commit:       %s\n", OQS_COMPILE_GIT_COMMIT);
#endif
#if defined(OQS_USE_OPENSSL)
	printf("OpenSSL enabled:  Yes (%s)\n", OPENSSL_VERSION_TEXT);
#else
	printf("OpenSSL enabled:  No\n");
#endif
#if defined(OQS_USE_AES_OPENSSL)
	printf("AES:              OpenSSL\n");
#else
	AES_C_OR_NI_OR_ARM(
		printf("AES:              C\n"),
		printf("AES:              NI\n"),
		printf("AES:              C and ARM CRYPTO extensions\n"));
#endif
#if defined(OQS_USE_SHA2_OPENSSL)
	printf("SHA-2:            OpenSSL\n");
#else
	SHA2_C_OR_ARM(
		printf("SHA-2:            C\n"),
		printf("SHA-2:            C and ARM CRYPTO extensions\n"));
#endif
#if defined(OQS_USE_SHA3_OPENSSL)
	printf("SHA-3:            OpenSSL\n");
#else
	printf("SHA-3:            C\n");
#endif
	printf("OQS build flags:  ");
#ifdef BUILD_SHARED_LIBS
	printf("BUILD_SHARED_LIBS ");
#endif
#ifdef OQS_ENABLE_TEST_CONSTANT_TIME
	printf("OQS_ENABLE_TEST_CONSTANT_TIME ");
#endif
#ifdef OQS_SPEED_USE_ARM_PMU
	printf("OQS_SPEED_USE_ARM_PMU ");
#endif
#ifdef OQS_DIST_BUILD
	printf("OQS_DIST_BUILD ");
#endif
#ifdef OQS_BUILD_ONLY_LIB
	printf("OQS_BUILD_ONLY_LIB "); // pretty much impossible to appear but added for completeness
#endif
#ifdef USE_SANITIZER
	printf("USE_SANITIZER=%s ", USE_SANITIZER);
#endif
#ifdef OQS_OPT_TARGET
	printf("OQS_OPT_TARGET=%s ", OQS_OPT_TARGET);
#endif
#ifdef CMAKE_BUILD_TYPE
	printf("CMAKE_BUILD_TYPE=%s ", CMAKE_BUILD_TYPE);
#else
#ifdef OQS_DEBUG_BUILD
	guard against impossible configuration(no CMAKE_BUILD_TYPE but DEBUG_BUILD)
#endif
		printf("CMAKE_BUILD_TYPE=Release ");
#endif
	printf("\n");
}

int main(int argc, char *argv[])
{
	printf("System info\r\n==================\r\n");
	print_platform_info();
	print_compiler_info();
	print_oqs_configuration();
	print_cpu_extensions();
	printf("\r\n\r\n");

	printf("Project info\r\n==================\r\n");
	if (DEBUG_MODE)
		printf("DEBUG_MODE:   enabled\n");
	else
		printf("DEBUG_MODE:   disabled\n");
	printf("BUILD_TIME:   %s\r\n", BUILD_TIME);
	printf("PROJECT_NAME: %s\r\n", PROJECT_NAME);
	printf("PROJECT_VER:  %s (%d.%d.%d)\r\n", PROJECT_VER, PROJECT_VER_MAJOR, PROJECT_VER_MINOR, PTOJECT_VER_PATCH);
	printf("\r\n");

	printf("Device info\r\n==================\r\n");
	printf("[SPI]\r\n");
	if (SPI_DEV_ENABLED)
	{
		printf("SPI_DEV_ENABLED: true\r\n");
		printf("SPI_DEV_NAME: %s\r\n", SPI_DEV_NAME);
		printf("SPI_MODE: %d\r\n", SPI_MODE);
		printf("SPI_BITS_PER_WORD: %d\r\n", SPI_BITS_PER_WORD);
		printf("SPI_MAX_SPEED_HZ: %d\r\n", SPI_MAX_SPEED_HZ);
		printf("SPI_BUFFER_SIZE: %d\r\n", SPI_BUFFER_SIZE);
		printf("SPI_PACKET_DATA_SIZE: %d\r\n", SPI_PACKET_DATA_SIZE);
	}
	else
	{
		printf("SPI_DEV_ENABLED: false\r\n");
	}
	printf("\r\n");
	printf("[UART]\r\n");
	if (UART_DEV_ENABLED)
	{
		printf("UART_DEV_ENABLED: true\r\n");
		printf("UART_DEV_NAME: %s\r\n", UART_DEV_NAME);
		printf("UART_OPEN_FLAGS: 0x%08X\r\n", UART_OPEN_FLAGS);
		printf("UART_INPUT_MODE_FLAGS: 0x%08X\r\n", UART_INPUT_MODE_FLAGS);
		printf("UART_OUTPUT_MODE_FLAGS: 0x%08X\r\n", UART_OUTPUT_MODE_FLAGS);
		printf("UART_CONTROL_MODE_FLAGS: 0x%08X\r\n", UART_CONTROL_MODE_FLAGS);
		printf("UART_LOCAL_MODE_FLAGS: 0x%08X\r\n", UART_LOCAL_MODE_FLAGS);
		printf("UART_BUFFER_SIZE: %d\r\n", UART_BUFFER_SIZE);
		printf("UART_PACKET_DATA_SIZE: %d\r\n", UART_PACKET_DATA_SIZE);
	}
	else
	{
		printf("UART_DEV_ENABLED: false\r\n");
	}
	printf("\r\n");

	PASS_n_EXIT;
}
