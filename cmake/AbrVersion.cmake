# abr's version: 1.YYYYMMDD.N
#
#   1         the major version
#   YYYYMMDD  the date (UTC) of the commit that is built -- not the clock of the machine, so that the same sources give the same version
#   N         the number of the build of that day: how many commits of that date are in the history of the commit that is built
#             (a checkout without history has one)
#
# A release pipeline that numbers its builds in some other way sets the pieces itself, as -DABR_BUILD_DATE=20261102 and
# -DABR_BUILD_NUMBER=5 or as environment variables of the same names. Without git (a tarball of the sources) the date is the day of the
# configuration and N is 0.
#
# Defines ABR_VERSION (the string) and writes <build dir>/generated/abr/version.hpp, which src/main.cpp includes.

set(ABR_VERSION_MAJOR 1)

if(NOT ABR_BUILD_DATE AND DEFINED ENV{ABR_BUILD_DATE})
  set(ABR_BUILD_DATE "$ENV{ABR_BUILD_DATE}")
endif()
if(NOT ABR_BUILD_NUMBER AND DEFINED ENV{ABR_BUILD_NUMBER})
  set(ABR_BUILD_NUMBER "$ENV{ABR_BUILD_NUMBER}")
endif()

find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
  # A new commit (the reflog of HEAD grows) configures again, so that the version follows the history.
  foreach(_abr_git_file HEAD logs/HEAD)
    if(EXISTS "${CMAKE_SOURCE_DIR}/.git/${_abr_git_file}")
      set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/.git/${_abr_git_file}")
    endif()
  endforeach()
  if(NOT ABR_BUILD_DATE)
    execute_process(
      COMMAND ${CMAKE_COMMAND} -E env TZ=UTC ${GIT_EXECUTABLE} log -1 --format=%cd --date=format-local:%Y%m%d
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" OUTPUT_VARIABLE _abr_commit_date ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(_abr_commit_date MATCHES "^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$")
      set(ABR_BUILD_DATE "${_abr_commit_date}")
    endif()
  endif()
  if(NOT ABR_BUILD_NUMBER AND ABR_BUILD_DATE MATCHES "^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$")
    string(SUBSTRING "${ABR_BUILD_DATE}" 0 4 _y)
    string(SUBSTRING "${ABR_BUILD_DATE}" 4 2 _m)
    string(SUBSTRING "${ABR_BUILD_DATE}" 6 2 _d)
    execute_process(
      COMMAND ${GIT_EXECUTABLE} rev-list --count "--after=${_y}-${_m}-${_d}T00:00:00Z" "--before=${_y}-${_m}-${_d}T23:59:59Z" HEAD
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" OUTPUT_VARIABLE _abr_count ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(_abr_count MATCHES "^[0-9]+$")
      set(ABR_BUILD_NUMBER "${_abr_count}")
    endif()
  endif()
endif()
if(NOT ABR_BUILD_DATE)
  string(TIMESTAMP ABR_BUILD_DATE "%Y%m%d" UTC)
endif()
if(NOT ABR_BUILD_NUMBER)
  set(ABR_BUILD_NUMBER 0)
endif()
if(NOT ABR_BUILD_DATE MATCHES "^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$")
  message(FATAL_ERROR "ABR_BUILD_DATE must be YYYYMMDD, not '${ABR_BUILD_DATE}'")
endif()
if(NOT ABR_BUILD_NUMBER MATCHES "^[0-9]+$")
  message(FATAL_ERROR "ABR_BUILD_NUMBER must be a whole number, not '${ABR_BUILD_NUMBER}'")
endif()

set(ABR_VERSION "${ABR_VERSION_MAJOR}.${ABR_BUILD_DATE}.${ABR_BUILD_NUMBER}")
message(STATUS "abr version ${ABR_VERSION}")

file(WRITE "${CMAKE_BINARY_DIR}/generated/abr/version.hpp.in"
"// Written by cmake/AbrVersion.cmake -- do not edit.
#pragma once
namespace abr {
inline constexpr const char* kVersion = \"@ABR_VERSION@\";
}  // namespace abr
")
configure_file("${CMAKE_BINARY_DIR}/generated/abr/version.hpp.in" "${CMAKE_BINARY_DIR}/generated/abr/version.hpp" @ONLY)
