cmake_minimum_required(VERSION 3.18)
project(agent-sandbox-exec VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Which user's agents we confine (cgroup delegation target). Overridable on the
# cmake command line: -DAGENT_USER=...
set(AGENT_USER "owner" CACHE STRING "User whose agents are confined (cgroup delegation target)")

# --- toolchain discovery -----------------------------------------------------
find_program(CLANG      clang       REQUIRED)
find_program(BPFTOOL    bpftool     REQUIRED)
find_program(LLVM_STRIP llvm-strip)

include(FindPkgConfig)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(ZLIB   REQUIRED IMPORTED_TARGET zlib)

message(STATUS "clang      : ${CLANG}")
message(STATUS "bpftool    : ${BPFTOOL}")
message(STATUS "libbpf     : ${LIBBPF_VERSION}")

# The BPF program + daemon targets are added in later commits.

# --- install of the launcher/unit/denylist is wired in a later commit --------
