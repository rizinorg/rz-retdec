
set(file "${retdec_path}/deps/yara/CMakeLists.txt")

file(READ "${file}" content)
set(new_content "${content}")

# https://github.com/avast/retdec/pull/1127
string(REPLACE
	"option(YARA_MAKE_PROGRAM \"A path to make tool which should be used to compile yara\" \"make\")"
	"set(YARA_MAKE_PROGRAM \"make\" CACHE STRING \"A path to make tool which should be used to compile yara\")"
    new_content
    "${new_content}"
)

if("${new_content}" STREQUAL "${content}")
    message(STATUS "-- Patching: ${file} skipped")
else()
    message(STATUS "-- Patching: ${file} patched")
    file(WRITE "${file}" "${new_content}")
endif()
