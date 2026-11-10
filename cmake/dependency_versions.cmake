# The versions of the libraries that abr is built with -- the one place for them. CMakeLists.txt reads this file; tools/check_deps.py
# (run weekly by .github/workflows/deps.yml) reads it too, and asks the repository of each library whether a newer release is out.
#
# They are plain variables and not cache entries, so that a build directory that is configured again picks up a change made here
# (a cache entry would keep the value of the first configure). A value given on the command line (-DABR_ZLIB_VERSION=1.3.2) wins.
# A cache entry that the older `set(... CACHE STRING "")` pins left in a build directory is dropped.
#
#   -DABR_DEPS_LATEST=ON   builds with the newest release that the repository of each library tags, whatever is written below
#                          (it asks with `git ls-remote` when cmake configures; see cmake/vendor_deps.cmake). For trying a release that is
#                          not here yet: the build of the shipping binaries uses the versions below, so that it can be repeated.
#
# LZO is not in this list: it has no repository of its own (the releases are tarballs), and its latest release, 2.10 of March 2017, is the
# one in third_party/lzo.

macro(abr_pin name value)
  if(DEFINED CACHE{${name}})
    get_property(_abr_help CACHE ${name} PROPERTY HELPSTRING)
    if(_abr_help STREQUAL "")
      unset(${name} CACHE)
    endif()
  endif()
  if(NOT DEFINED ${name})
    set(${name} "${value}")
  endif()
endmacro()

abr_pin(ABR_ZLIB_VERSION  "1.4")      # 4 Nov 2026: security fixes (gzwrite, inflateGetDictionary, inflatePrime/deflatePrime, inflateBack, ...)
abr_pin(ABR_LZ4_VERSION   "1.11.1")   # 9 Nov 2026 (1.11.0 of 3 Nov: multithreaded lz4frame, LZ4F_preferences_t.nbWorkers, and fixes of data corruption in rare cases;
                                      # 1.11.1: a write out of bounds of LZ4_resetStreamHC() at levels 10 and up, which 1.11.0 has)
abr_pin(ABR_ZSTD_VERSION  "1.5.7")
abr_pin(ABR_XZ_VERSION    "5.8.4")
abr_pin(ABR_BZIP2_VERSION "1.0.8")    # the last release; CVE-2026-42250 is in the bzip2recover utility, which abr does not build

