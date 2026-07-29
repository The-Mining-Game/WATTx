// Minimal stub of epee's misc_log_ex.h for the isolated libwattx_bpplus port.
// Provides only the logging/assert macros that Monero's ringct/BP+ sources use,
// with no boost-log dependency. Assert-throw maps to std::runtime_error; the
// non-throwing assert returns the given value; logging goes to std::cerr.
#pragma once
#include <iostream>
#include <sstream>
#include <stdexcept>

#define MERROR(x)   do { std::cerr << x << std::endl; } while (0)
#define MWARNING(x) do { std::cerr << x << std::endl; } while (0)
#define MINFO(x)    do {} while (0)
#define MDEBUG(x)   do {} while (0)
#define MTRACE(x)   do {} while (0)
#define MGINFO(x)   do {} while (0)
#define LOG_PRINT_L0(x) do {} while (0)
#define LOG_PRINT_L1(x) do {} while (0)
#define LOG_PRINT_L2(x) do {} while (0)
#define LOG_ERROR(x) do { std::cerr << x << std::endl; } while (0)

#define CHECK_AND_ASSERT_THROW_MES(expr, message) \
    do { if (!(expr)) { std::stringstream _ss; _ss << message; throw std::runtime_error(_ss.str()); } } while (0)

#define CHECK_AND_ASSERT_MES(expr, fail_ret_val, message) \
    do { if (!(expr)) { std::cerr << message << std::endl; return fail_ret_val; } } while (0)

#define CHECK_AND_ASSERT(expr, fail_ret_val) \
    do { if (!(expr)) { return fail_ret_val; } } while (0)
