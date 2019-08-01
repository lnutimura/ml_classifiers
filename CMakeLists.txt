cmake_minimum_required ( VERSION 3.4.3 )
project ( ml_classifiers CXX )

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

set (CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} "/home/lnutimura/snort_src/boost_1_67_0")

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    ml_classifiers MODULE
    ml_classifiers.cc
    ml_classifiers.h
)

if ( APPLE )
    set_target_properties (
        ml_classifiers
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    ml_classifiers
    PROPERTIES
        PREFIX ""
)

find_package ( Boost )
if ( Boost_FOUND )
    message ( "[*] Found Boost" )
    include_directories ( ${Boost_INCLUDE_DIRS} )
    message ( "[*] Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}" )
endif ( Boost_FOUND )

target_include_directories (
    ml_classifiers PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS ml_classifiers
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/inspectors"
)
