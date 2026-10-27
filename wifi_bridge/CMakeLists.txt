cmake_minimum_required(VERSION 3.22)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# Each board resolves a different set of components, so keep one lock per target.
idf_build_set_property(DEPENDENCIES_LOCK "${CMAKE_CURRENT_LIST_DIR}/dependencies.lock.${IDF_TARGET}")
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/../src/lwIP.h" LWIP_CE_VERSION REGEX "^#define LWIP_CE_VERSION_STRING ")
string(REGEX REPLACE ".*\"(.*)\".*" "\\1" PROJECT_VER "${LWIP_CE_VERSION}")
project(lwip_wifi_bridge)
