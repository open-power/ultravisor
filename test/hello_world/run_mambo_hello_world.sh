#!/usr/bin/env bash

###############################################################################
#
#  Run Mambo
#
###############################################################################
set -euo pipefail
IFS=$'\n\t'

PROG=$(basename "${0}")
VERBOSE=${VERBOSE-0}

_LOG_DIR=$(mktemp -d /var/tmp/"${PROG}"_log.XXXXXX)
_LOG_FILE="${_LOG_DIR}/${PROG}.log"

# Reset
COLOR_OFF='\e[0m' # Text Reset

# Bold High Intensity
BIRED='\e[1;91m' # Red

# Define quiet versions of pushd and popd
pushd()
{
  builtin pushd "${@}" > /dev/null
}

#shellcheck disable=SC2120
popd()
{
  builtin popd "${@-}" > /dev/null
}

write_log ()
{
  while read -r _msg; do
    echo "$(date -Iseconds) ${PROG} [DEBUG]: ${_msg}" >> "${_LOG_FILE}"
    if [[ ${VERBOSE} -eq 1 ]]; then
      echo "${PROG} [DEBUG]: ${_msg}"
    fi
  done
}

write_stdout ()
{
  echo "${PROG} [INFO]: ${1}"
  echo "$(date -Iseconds) ${PROG} [INFO]: ${1}" >> "${_LOG_FILE}"
}

write_stderr ()
{
  echo -e "${PROG} ${BIRED}[ERROR]${COLOR_OFF}: ${1}" >&2
  echo -e "$(date -Iseconds) ${PROG} ${BIRED}[ERROR]${COLOR_OFF}: ${1}" >> "${_LOG_FILE}"
}

stderr_exit ()
{
  write_stderr "${1}"
  exit "${2}"
}

clean_up ()
{
  local _ec=$?

  # To help wtih debug cat log file on error exit.
  if [[ ${_ec} -ne 0 && ${VERBOSE} -ne 0 ]]; then
  write_stdout "Starting ${PROG}:${FUNCNAME[0]}"
  write_stdout "==========================DEBUG START==================================="
    cat "${_LOG_FILE}"
  write_stdout "==========================DEBUG END====================================="
  fi

  rm -f "${_LOG_FILE}"
  rmdir "${_LOG_DIR}"

  exit ${_ec}
}

trap clean_up SIGHUP SIGINT SIGTERM EXIT

run_test()
{

  ##
  # Exported values used by ultra.tcl
  ##

  #export VMLINUX_MAP
  #export SKIBOOT_MAP
  #export CPUS=1
  #export THREADS=1
  #export MEM_SIZE=4G
  #export MAMBO_IMG_DIR
  #export MAMBO_IMG_DIR
  #export SKIBOOT=skiboot.lid
  #export ULTRA_VMLINUX=vmlinux
  #export ULTRA_IMG=ultra.lid
  #export ROOTDISK=disk.img

  #export MAMBO_ENABLE_SMF=True
  #export MAMBO_ENABLE_ULTRA=none

  #export LINUX_CMDLINE=""

  #export MAMBO_SKIBOOT_LOAD=0x30000000
  #export MAMBO_SKIBOOT_PC=0x30000010
  #export VMLINUX_ADDR=0x20000000
  #export EPAPR_DT_ADDR=0x1f00000

  export MAMBO_ROOTDISK_COW=/var/tmp/rootdisk.cow
  export MAMBO_ROOTDISK_COW_METHOD=newcow
  export MAMBO_ROOTDISK_COW_HASH=1024

  pushd "${1}"

  "${MAMBO_PATH}"/"${MAMBO_RUN}" -n -f "${2}"

  #shellcheck disable=SC2119
  popd 
}

print_help ()
{
  cat <<-EndHelp

  Usage: ${PROG} [-h] [-s] <vmlinux_img>

  This script will run mambo with provided tcl script

  Optional arguments:

  -s, --smf
    Enable SMF mode.

  -h, --help
    Display ${PROG} help and exit.

EndHelp
}

main ()
{


#  local positionals=()
#  local vmlinux_img=""
#  local enable_smf=""
#
#  local run_dir
#  run_dir=$(readlink -f "${0}")
#  run_dir=$(dirname "${run_dir}")
#  local build_dir="${run_dir%%/test/hello_world}"
#
#  while [[ "$#" -gt 0 ]]; do
#    case "$1" in
#      -s|--smf)
#        enable_smf="True"
#        ;;
#      -h|--help)
#        print_help
#        exit 0
#        ;;
#      *)
#        positionals+=("$1")
#    esac
#    shift
#  done
#
#  [[ ${#positionals[@]} -lt 1 ]] && stderr_exit "Missing positional(s)" 1
#
#  vmlinux_img=${positionals[0]}
#
#  write_stdout "========================================================================"
#  write_stdout "${PROG}"
#  write_stdout "Vmlinux image: ${vmlinux_img}"
#  write_stdout "Log file: ${_LOG_FILE}"
#
#  write_stdout "========================================================================"
#
#  if [ -z "${MAMBO_PATH:-}" ]; then
#    MAMBO_PATH="/opt/ibm/systemsim-p9"
#  fi
#
#  if [ -z "${MAMBO_RUN:-}" ]; then
#    MAMBO_RUN="run/p9/run_cmdline"
#  fi
#
#  if [ ! -x "$MAMBO_PATH/$MAMBO_RUN" ]; then
#    write_stderr 'Could not find Mambo run command. Skipping test'
#    exit 1
#  fi
#
#  if [ -z "${MAMBO_IMG_DIR:-}" ]; then
#    echo 'MAMBO_IMG_DIR not set will use ultra-ci/images image dir'
#    export MAMBO_IMG_DIR="${build_dir}/ultra-ci/images"
#    echo "${MAMBO_IMG_DIR}"
#  fi
#
#  if [ ! -z "${enable_smf}" ]; then
#    export MAMBO_ENABLE_SMF=True
#    export MAMBO_ENABLE_ULTRA=True
#  fi
#
#  export ULTRA_VMLINUX="${vmlinux_img}"
#
#  run_test "${build_dir}/external/mambo/" "${run_dir}/run_hello.tcl"

  exit 0
}

main "$@"
