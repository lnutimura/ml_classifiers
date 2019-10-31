cmake_minimum_required ( VERSION 3.4.3 )
project ( ml_classifiers CXX )

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

set (CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} "/home/lnutimura/snort_src/boost_1_67_0")
#set (CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} "/usr/include/python3.7")

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

find_package ( Python3 COMPONENTS Interpreter Development )
if ( Python3_FOUND )
    find_package ( Boost COMPONENTS python${Python3_VERSION_MAJOR}${Python3_VERSION_MINOR} )
endif ( Python3_FOUND )

message ( "[*] PYTHON_LIBRARY_DIRS: ${Python3_LIBRARY_DIRS}" )
message ( "[*] PYTHON_LIBRARIES: ${Python3_LIBRARIES}" )
message ( "[*] PYTHON_EXECUTABLE: ${Python3_EXECUTABLE}" )
message ( "[*] PYTHON_INCLUDE_DIRS: ${Python3_INCLUDE_DIRS}" )

message ( "[*] BOOST_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}" )
message ( "[*] BOOST_LIBRARIES: ${Boost_LIBRARIES}" )
message ( "[*] BOOST_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}" )

include_directories ( ${Python3_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS} )
target_link_libraries ( ml_classifiers ${Python3_LIBRARIES} ${Boost_LIBRARIES} )

target_include_directories (
    ml_classifiers PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS ml_classifiers
    LIBRARY
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_PROJECT_NAME}/inspectors"
)
