cmake_minimum_required(VERSION 3.16)
project(ml_classifiers CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SNORT3 snort>=3)

add_executable(test_flow_features
    test/test_flow_features.cc
    src/flow_features.cc
)
target_include_directories(test_flow_features PRIVATE src)
target_compile_options(test_flow_features PRIVATE -Wall -Wextra -Werror)

enable_testing()
add_test(NAME flow_features COMMAND test_flow_features)

if(NOT SNORT3_FOUND)
    message(STATUS "snort>=3 was not found; the inspector module will not be built")
    return()
endif()

find_package(Python3 REQUIRED COMPONENTS Development)

add_library(ml_classifiers MODULE
    src/ml_classifiers.cc
    src/connection.cc
    src/flow_features.cc
    src/classifier.cc
)

set_target_properties(ml_classifiers PROPERTIES PREFIX "")

target_include_directories(ml_classifiers PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${SNORT3_INCLUDE_DIRS}
    ${Python3_INCLUDE_DIRS}
)
target_compile_options(ml_classifiers PRIVATE -Wall -Wextra ${SNORT3_CFLAGS_OTHER})
target_compile_definitions(ml_classifiers PRIVATE
    HAVE_VISIBILITY
    ML_CLASSIFIERS_SCRIPT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/python"
)
target_link_libraries(ml_classifiers PRIVATE
    ${Python3_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

add_custom_command(TARGET ml_classifiers POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:ml_classifiers>/ml_py
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/python/ml_classifiers.py
        $<TARGET_FILE_DIR:ml_classifiers>/ml_py/ml_classifiers.py
    VERBATIM
)

install(TARGETS ml_classifiers
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/snort/inspectors"
)
install(FILES python/ml_classifiers.py
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/snort/inspectors/ml_py"
)

if(APPLE)
    set_target_properties(ml_classifiers PROPERTIES
        LINK_FLAGS "-undefined dynamic_lookup"
    )
endif()
