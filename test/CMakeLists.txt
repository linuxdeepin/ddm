find_package(Qt6 CONFIG REQUIRED Test)

add_executable(tst_forkexitguard
    tst_forkexitguard.cpp
)

target_include_directories(tst_forkexitguard PRIVATE
    "${CMAKE_SOURCE_DIR}/src/daemon"
)

target_link_libraries(tst_forkexitguard PRIVATE
    Qt6::Test
)

add_test(NAME tst_forkexitguard COMMAND tst_forkexitguard)
