cmake_minimum_required(VERSION 3.8)

if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/retdec")
	set(retdec_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/retdec")
	set(retdec_BINARY_DIR "")
else()
	include(FetchContent)

	FetchContent_Declare(retdec
		GIT_REPOSITORY https://github.com/avast/retdec
		GIT_TAG 53e55b4b26e9b843787f0e06d867441e32b1604e # v5
		PATCH_COMMAND ${CMAKE_COMMAND} -Dretdec_path=<SOURCE_DIR> -P ${CMAKE_CURRENT_SOURCE_DIR}/patch.cmake
	)

	FetchContent_GetProperties(retdec)
	if(NOT retdec_POPULATED)
		FetchContent_Populate(retdec)
	endif()
endif()

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
