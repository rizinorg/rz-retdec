cmake_minimum_required(VERSION 3.8)

include(FetchContent)

FetchContent_Declare(retdec
	GIT_REPOSITORY https://github.com/avast/retdec
	GIT_TAG 73184b0c17b8790ab691217d2ab4cb6d569495fb
)

FetchContent_GetProperties(retdec)
if(NOT retdec_POPULATED)
	FetchContent_Populate(retdec)

	# Override some archives because the original URLs are broken
	set(YARA_URL "https://github.com/rizinorg/rz-retdec-deps/releases/download/retdec-73184b0c/yara.zip" CACHE STRING "")
	set(CAPSTONE_URL "https://github.com/rizinorg/rz-retdec-deps/releases/download/retdec-73184b0c/capstone.zip" CACHE STRING "")
	set(LLVM_URL "https://github.com/rizinorg/rz-retdec-deps/releases/download/retdec-73184b0c/llvm.zip" CACHE STRING "")
	set(YARAMOD_URL "https://github.com/rizinorg/rz-retdec-deps/releases/download/retdec-73184b0c/yaramod.zip" CACHE STRING "")
	add_subdirectory(
		${retdec_SOURCE_DIR}
		${retdec_BINARY_DIR}
	)

	install(
		DIRECTORY
			"${retdec_SOURCE_DIR}/support/ordinals"
			"${retdec_SOURCE_DIR}/support/yara_patterns"
			"${retdec_SOURCE_DIR}/support/types"
		DESTINATION
			"${RIZIN_INSTALL_PLUGDIR}/support/retdec/"
	)
endif()
