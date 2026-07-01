cmake_minimum_required(VERSION 3.18)
project(agent-sandbox-exec VERSION 0.1.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Install under /usr (Debian convention for a system package). Overridable on
# the cmake command line with -DCMAKE_INSTALL_PREFIX=...
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Install prefix" FORCE)
endif()

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

# Optional BPF debug-info strip; skipped (not fatal) if llvm-strip is absent.
if(LLVM_STRIP)
  set(STRIP_CMD ${LLVM_STRIP} -g ${BPF_OBJ})
else()
  message(STATUS "llvm-strip not found; BPF debug-info strip will be skipped")
  set(STRIP_CMD ${CMAKE_COMMAND} -E echo "agent-sandbox-exec: llvm-strip absent, skipping BPF strip")
endif()

# Compile the BPF program to an object.
add_custom_command(
  OUTPUT ${BPF_OBJ}
  COMMAND ${CLANG} -g -O2 -Wall -target bpf -D__TARGET_ARCH_x86
          -I${CMAKE_CURRENT_BINARY_DIR} -I${CMAKE_CURRENT_SOURCE_DIR}/src
          -c ${BPF_SRC} -o ${BPF_OBJ}
  COMMAND ${STRIP_CMD}
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
add_executable(agent-sandbox-execd src/agent-sandbox-execd.c)
target_include_directories(agent-sandbox-execd PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}        # agent_sandbox.skel.h
  ${CMAKE_CURRENT_SOURCE_DIR}/src)   # agent_sandbox.h
target_link_libraries(agent-sandbox-execd PRIVATE PkgConfig::LIBBPF PkgConfig::LIBELF PkgConfig::ZLIB)
add_dependencies(agent-sandbox-execd bpf_skel)


# --- install rules (used by both `cmake --install` and CPack) ----------------
include(GNUInstallDirs)

install(TARGETS agent-sandbox-execd
        RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})        # /usr/local/sbin

install(PROGRAMS scripts/agent-sandbox-exec.sh
        DESTINATION ${CMAKE_INSTALL_BINDIR}                  # /usr/local/bin
        RENAME agent-sandbox-exec)

# Vendor systemd unit lives under /usr/lib/systemd/system (not /etc), so dpkg
# owns its lifecycle across upgrades and admins can still drop an override in
# /etc/systemd/system. Not marked as a conffile.
install(FILES scripts/agent-sandbox-execd.service
        DESTINATION lib/systemd/system)

install(FILES scripts/denylist.example
        DESTINATION /etc/agent-sandbox-exec
        RENAME denylist)

# man pages
install(FILES man/agent-sandbox-exec.1     DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES man/agent-sandbox-exec-denylist.5 DESTINATION ${CMAKE_INSTALL_MANDIR}/man5)

# --- packaging (.deb via CPack) ---------------------------------------------
set(CPACK_GENERATOR                  DEB)
set(CPACK_PACKAGE_NAME               "agent-sandbox-exec")
set(CPACK_PACKAGE_VERSION            "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "BPF-LSM file-read denylist for CLI agents")
set(CPACK_PACKAGE_CONTACT            "owner <owner@localhost>")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER  "owner")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
# Debian-style filename (name_version_arch.deb) so `make install` can glob
# agent-sandbox-exec_*.deb. Without this CPack defaults to a hyphenated name
# the Makefile target does not match.
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}_${PROJECT_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
set(CPACK_DEBIAN_PACKAGE_SECTION     "admin")
set(CPACK_DEBIAN_PACKAGE_PRIORITY    "optional")
set(CPACK_DEBIAN_PACKAGE_DEPENDS     "libbpf1, libelf1, zlib1g")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/postinst
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/prerm
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/postrm
  ${CMAKE_CURRENT_SOURCE_DIR}/packaging/conffiles)
include(CPack)
