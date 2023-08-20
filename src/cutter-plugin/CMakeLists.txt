if (NOT BUILD_BUNDLED_RETDEC)
	set(RETDEC_VERSION 5.0)
	find_package(retdec ${RETDEC_VERSION} REQUIRED COMPONENTS retdec config)
endif()

set(CUTTER_PLUGIN_INCLUDE ${PROJECT_SOURCE_DIR}/include/cutter-plugin)

set(SOURCE
	${CUTTER_PLUGIN_INCLUDE}/core_plugin.h
	core_plugin.cpp
)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_library(retdec_cutter MODULE ${SOURCE})
target_include_directories(retdec_cutter PUBLIC ${PROJECT_SOURCE_DIR}/include/)
target_link_libraries(retdec_cutter PUBLIC core_retdec Cutter::Cutter)

install(TARGETS retdec_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
