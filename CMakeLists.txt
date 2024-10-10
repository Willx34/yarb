cmake_minimum_required(VERSION 3.20)

# Set CMake policy to use the traditional method for finding Boost components
cmake_policy(SET CMP0167 OLD)

set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

# Ensure to pick up the default triplet from the environment if any.
if (NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# Set the required Boost version
set(BOOST_REQUIRED_VERSION 1.75.0)

# Define options
option(HTTP "Enable HTTP support" ON)
option(BUILD_TESTING "Build unit tests" OFF)
option(USE_LUAJIT "Use LuaJIT" OFF)

if (HTTP)
    list(APPEND VCPKG_MANIFEST_FEATURES "http")
endif()

if (BUILD_TESTING)
    list(APPEND VCPKG_MANIFEST_FEATURES "unit-tests")
endif()

if (USE_LUAJIT)
    list(APPEND VCPKG_MANIFEST_FEATURES "luajit")
else()
    list(APPEND VCPKG_MANIFEST_FEATURES "lua")
endif()

project(tfs CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Compiler-specific options
if (NOT WIN32)
    add_compile_options(-Wall -Wextra -Wnon-virtual-dtor -Wold-style-cast -pedantic -Werror -pipe -fvisibility=hidden)
endif()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    add_compile_options(-fno-strict-aliasing)
endif()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    add_compile_options(-Wimplicit-fallthrough -Wmove)
endif()

# Find required packages
find_package(OpenSSL 3.0.0 REQUIRED COMPONENTS Crypto)
find_package(fmt 8.1.1 CONFIG REQUIRED)

# Look for vcpkg-provided libmariadb first
find_package(unofficial-libmariadb CONFIG)
if (unofficial-libmariadb_FOUND)
   set(MYSQL_CLIENT_LIBS unofficial::libmariadb)
else()
    find_package(MySQL REQUIRED)
endif()

find_package(Threads REQUIRED)
find_package(pugixml CONFIG REQUIRED)

# Find Lua or LuaJIT
if (USE_LUAJIT)
    find_package(LuaJIT REQUIRED)
else()
    find_package(Lua REQUIRED)
endif()

if (APPLE)
    find_package(Iconv REQUIRED)
endif()

# Define the required Boost components
set(BOOST_REQUIRED_COMPONENTS system iostreams locale regex container)

if (HTTP)
    list(APPEND BOOST_REQUIRED_COMPONENTS json)
endif()

if (BUILD_TESTING)
    list(APPEND BOOST_REQUIRED_COMPONENTS unit_test_framework)
endif()

find_package(Boost ${BOOST_REQUIRED_VERSION} REQUIRED COMPONENTS ${BOOST_REQUIRED_COMPONENTS})

# Set the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable testing if requested
if (BUILD_TESTING)
    message(STATUS "Building unit tests")
    enable_testing()
endif()

# Option to disable unity builds
option(ENABLE_UNITY_BUILD "Enable unity build" ON)

# Add the source directory
add_subdirectory(src)

# Create the executable (Moved up before target modifications)
add_executable(tfs ${tfs_MAIN})

# Include Boost headers
target_include_directories(tfs PRIVATE ${Boost_INCLUDE_DIRS})

# Link libraries
target_link_libraries(tfs PRIVATE
    tfslib
    Boost::boost
    Boost::system
    Boost::iostreams
    Boost::locale
    Boost::regex
    Boost::container
    OpenSSL::Crypto
    Threads::Threads
    fmt::fmt
    pugixml::pugixml
    ${MYSQL_CLIENT_LIBS}
)

if (HTTP)
    target_link_libraries(tfs PRIVATE
        Boost::json
    )
endif()

# Include directories and link libraries for Lua
if (USE_LUAJIT)
    target_include_directories(tfs PRIVATE ${LUAJIT_INCLUDE_DIR})
    target_link_libraries(tfs PRIVATE ${LUAJIT_LIBRARIES})
else()
    target_include_directories(tfs PRIVATE ${LUA_INCLUDE_DIR})
    target_link_libraries(tfs PRIVATE ${LUA_LIBRARIES})
endif()

if (APPLE)
    target_link_libraries(tfs PRIVATE Iconv::Iconv)
endif()

# Get the include directories from pugixml::pugixml and add them to the target
get_target_property(PUGIXML_INCLUDE_DIRS pugixml::pugixml INTERFACE_INCLUDE_DIRECTORIES)
if (PUGIXML_INCLUDE_DIRS)
    target_include_directories(tfs PRIVATE ${PUGIXML_INCLUDE_DIRS})
endif()

# Now set the precompiled headers
target_precompile_headers(tfs PUBLIC src/otpch.h)

# Enable interprocedural optimization if supported
### INTERPROCEDURAL_OPTIMIZATION ###
include(CheckIPOSupported)
check_ipo_supported(RESULT result OUTPUT error)
if (result)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(STATUS "IPO is not supported: ${error}")
endif()
### END INTERPROCEDURAL_OPTIMIZATION ###

# Git version information
### Git Version
