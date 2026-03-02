cmake_minimum_required(VERSION 3.16)
project(messenger-client-cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CORE_SOURCES
    src/crypto.cpp
    src/message.cpp
    src/messenger_client.cpp
    src/websocket_messenger_client.cpp
    src/http_messenger_client.cpp
    src/remote_port_forwarder.cpp
)

set(CORE_LIBS
    bcrypt
    winhttp
    ws2_32
)

# Executable
add_executable(${PROJECT_NAME}
    src/main.cpp
    ${CORE_SOURCES}
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${CORE_LIBS}
)

# DLL
add_library(${PROJECT_NAME}-dll SHARED
    src/dllmain.cpp
    ${CORE_SOURCES}
)

set_target_properties(${PROJECT_NAME}-dll PROPERTIES
    OUTPUT_NAME ${PROJECT_NAME}
)

target_include_directories(${PROJECT_NAME}-dll PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME}-dll PRIVATE
    ${CORE_LIBS}
)
