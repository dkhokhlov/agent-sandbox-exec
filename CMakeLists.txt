cmake_minimum_required(VERSION 3.18)
project(agent-sandbox-exec VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Install under /usr (Debian convention for a system package). Overridable on
# the cmake command line with -DCMAKE_INSTALL_PREFIX=...
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Install prefix" FORCE)
endif()

# Which user's agents we confine (cgroup delegation target). Overridable on the
# cmake command line: -DAGENT_USER=...
set(AGENT_USER "owner" CACHE STRING "User whose agents are confined (cgroup delegation target)")

# --- toolchain discovery -----------------------------------------------------
find_program(CLANG      clang       REQUIRED)
# Debian ships bpftool in /usr/sbin (not on a normal user's PATH).
find_program(BPFTOOL NAMES bpftool PATHS /usr/sbin /usr/bin /usr/local/sbin /usr/local/bin REQUIRED)
find_program(LLVM_STRIP llvm-strip)

include(FindPkgConfig)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
pkg_check_modules(ZLIB   REQUIRED IMPORTED_TARGET zlib)

message(STATUS "clang      : ${CLANG}")
message(STATUS "bpftool    : ${BPFTOOL}")
message(STATUS "libbpf     : ${LIBBPF_VERSION}")

# --- BPF program: vmlinux.h, compile, skeleton ------------------------------
set(BPF_SRC   ${CMAKE_CURRENT_SOURCE_DIR}/src/agent_sandbox.bpf.c)
set(BPF_OBJ   ${CMAKE_CURRENT_BINARY_DIR}/agent_sandbox.bpf.o)
set(VMLINUX_H ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)
set(SKEL_H    ${CMAKE_CURRENT_BINARY_DIR}/agent_sandbox.skel.h)

# vmlinux.h from the running kernel's BTF (CO-RE).
add_custom_command(
  OUTPUT ${VMLINUX_H}
  COMMAND ${CMAKE_COMMAND} -E echo "Generating vmlinux.h"
  COMMAND sh -c "${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}"
  DEPENDS ${BPF_SRC}
  COMMENT "Generating vmlinux.h from /sys/kernel/btf/vmlinux"
  VERBATIM)

# Compile the BPF program to an object.
add_custom_command(
  OUTPUT ${BPF_OBJ}
  COMMAND ${CLANG} -g -O2 -Wall -target bpf -D__TARGET_ARCH_x86
          -I${CMAKE_CURRENT_BINARY_DIR} -I${CMAKE_CURRENT_SOURCE_DIR}/src
          -c ${BPF_SRC} -o ${BPF_OBJ}
  COMMAND ${LLVM_STRIP} -g ${BPF_OBJ}
  DEPENDS ${BPF_SRC} ${VMLINUX_H}
  COMMENT "Compiling BPF program (agent_sandbox.bpf.c)"
  VERBATIM)

# Generate the libbpf skeleton consumed by the daemon.
add_custom_command(
  OUTPUT ${SKEL_H}
  COMMAND sh -c "${BPFTOOL} gen skeleton ${BPF_OBJ} > ${SKEL_H}"
  DEPENDS ${BPF_OBJ}
  COMMENT "Generating BPF skeleton (agent_sandbox.skel.h)"
  VERBATIM)

add_custom_target(bpf_skel DEPENDS ${SKEL_H})

# --- daemon -----------------------------------------------------------------
add_executable(sandboxd src/sandboxd.c)
target_include_directories(sandboxd PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}        # agent_sandbox.skel.h
  ${CMAKE_CURRENT_SOURCE_DIR}/src)   # agent_sandbox.h
target_compile_definitions(sandboxd PRIVATE "AGENT_USER=\"${AGENT_USER}\"")
target_link_libraries(sandboxd PRIVATE PkgConfig::LIBBPF PkgConfig::LIBELF PkgConfig::ZLIB)
add_dependencies(sandboxd bpf_skel)


# --- install rules (used by both `cmake --install` and CPack) ----------------
include(GNUInstallDirs)

install(TARGETS sandboxd
        RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})        # /usr/local/sbin

install(PROGRAMS scripts/agent-sandbox-exec.sh
        DESTINATION ${CMAKE_INSTALL_BINDIR}                  # /usr/local/bin
        RENAME agent-sandbox-exec)

install(FILES scripts/agent-sandbox.service
        DESTINATION /etc/systemd/system)

install(FILES scripts/denylist.example
        DESTINATION /etc/agent-sandbox
        RENAME denylist)

# man pages
install(FILES man/agent-sandbox-exec.1     DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES man/agent-sandbox-denylist.5 DESTINATION ${CMAKE_INSTALL_MANDIR}/man5)

# --- packaging (.deb via CPack) ---------------------------------------------
set(CPACK_GENERATOR                  DEB)
set(CPACK_PACKAGE_NAME               "agent-sandbox-exec")
set(CPACK_PACKAGE_VERSION            "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "BPF-LSM file-read denylist for CLI agents")
set(CPACK_PACKAGE_CONTACT            "owner <owner@localhost>")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER  "owner")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_SECTION     "admin")
set(CPACK_DEBIAN_PACKAGE_PRIORITY    "optional")
set(CPACK_DEBIAN_PACKAGE_DEPENDS     "libbpf1, libelf1, zlib1g")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/postinst
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/prerm
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/postrm
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/conffiles)
include(CPack)
