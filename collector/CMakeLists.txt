cmake_minimum_required(VERSION 3.15)

project(DefenderAtlasCollector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(defenderatlas_collector
    main.cpp
    collector.cpp
    collector.h
    procmon.cpp
    procmon.h
    attachment_trigger.cpp
    attachment_trigger.h
    itrigger.h
    istrategy.h
    timeout_strategy.cpp
    timeout_strategy.h
    dataset.cpp
    dataset.h
    experiment.cpp
    experiment.h
    metadata.cpp
    metadata.h
    config.cpp
    config.h
    json.cpp
    json.h
    log.cpp
    log.h
    util.cpp
    util.h
)

target_link_libraries(defenderatlas_collector PRIVATE
    ole32
    wintrust
    crypt32
    bcrypt
)

if(MSVC)
    target_compile_options(defenderatlas_collector PRIVATE /W4 /utf-8)
else()
    target_compile_options(defenderatlas_collector PRIVATE -Wall -Wextra)
endif()
