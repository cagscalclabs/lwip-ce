cmake_minimum_required(VERSION 3.22)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# Each board resolves a different set of components, so keep one lock per target.
idf_build_set_property(DEPENDENCIES_LOCK "${CMAKE_CURRENT_LIST_DIR}/dependencies.lock.${IDF_TARGET}")
set(PROJECT_VER "1.0.0")
project(lwip_wifi_bridge)
