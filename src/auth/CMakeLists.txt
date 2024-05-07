set(PUBLIC_HEADERS
    ${CMAKE_SOURCE_DIR}/src/auth/Auth.h
    ${CMAKE_SOURCE_DIR}/src/auth/AuthMessages.h
    ${CMAKE_SOURCE_DIR}/src/auth/AuthPrompt.h
    ${CMAKE_SOURCE_DIR}/src/auth/AuthRequest.h
)

set(SRCS
    ${CMAKE_SOURCE_DIR}/src/auth/Auth.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/AuthPrompt.cpp
    ${CMAKE_SOURCE_DIR}/src/auth/AuthRequest.cpp
)

add_library(auth SHARED ${PUBLIC_HEADERS} ${SRCS})

set_target_properties(auth PROPERTIES
    VERSION ${CMAKE_PROJECT_VERSION}
    SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
    OUTPUT_NAME auth
    EXPORT_NAME Auth
)

target_link_libraries(auth
    PUBLIC
        common
        Qt${QT_MAJOR_VERSION}::Network
        Qt${QT_MAJOR_VERSION}::Qml
)

target_include_directories(auth INTERFACE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/auth>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/ddm/auth>
)
target_link_directories(auth INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_LIBDIR}>
)

if(PAM_FOUND)
    target_link_libraries(auth PUBLIC ${PAM_LIBRARIES})
else()
    target_link_libraries(auth PUBLIC crypt)
endif()


install(FILES ${PUBLIC_HEADERS} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/ddm/auth")
install(TARGETS auth EXPORT DDMAuthTargets DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(EXPORT DDMAuthTargets NAMESPACE DDM::Auth:: FILE DDMAuthTargets.cmake DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ddm")
