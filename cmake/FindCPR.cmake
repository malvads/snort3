find_package(PkgConfig)
pkg_check_modules(PC_CPR CPR)

if (PC_CPR_FOUND)
  set(CPR_LIBRARIES ${PC_CPR_LIBRARIES})
  set(CPR_INCLUDE_DIRS ${PC_CPR_INCLUDE_DIRS})
endif()

find_path(CPR_INCLUDE_DIR
  NAMES cpr.h
  HINTS ${CPR_INCLUDE_DIR_HINT} ${PC_CPR_INCLUDEDIR}
)

if (CPR_INCLUDE_DIR)
  message(STATUS "Found CPR include directory: ${CPR_INCLUDE_DIR}")
endif()

find_library(CPR_LIBRARY
  NAMES cpr
  HINTS ${CPR_LIBRARIES_DIR_HINT} ${PC_CPR_LIBDIR}
)

if (CPR_LIBRARY)
  message(STATUS "Found CPR library: ${CPR_LIBRARY}")
endif()

if (CPR_INCLUDE_DIR AND CPR_LIBRARY)
  set(HAVE_CPR TRUE)
  message(STATUS "CPR is found and usable.")

  set(CPR_LIBRARIES ${CPR_LIBRARY})
  set(CPR_INCLUDE_DIRS ${CPR_INCLUDE_DIR})
endif()

mark_as_advanced(
  CPR_INCLUDE_DIR
  CPR_LIBRARY
)

if (HAVE_CPR)
  add_library(cpr::cpr UNKNOWN IMPORTED)
  set_target_properties(cpr::cpr PROPERTIES
    IMPORTED_LOCATION "${CPR_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${CPR_INCLUDE_DIR}"
  )
endif()
