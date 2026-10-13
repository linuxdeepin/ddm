# The session helper. It is a standalone single-threaded QCoreApplication that
# runs the full PAM transaction (authenticate + open_session) and starts the
# user's desktop session. It deliberately links only against the "common"
# library (Configuration, Session, XAuth, ...) and must NOT pull in daemon-only
# machinery (DBus, display-server management, seatd control), so that it stays
# single-threaded and safe to fork() inside PAM modules.
set(HELPER_SOURCES
    HelperApp.cpp
    ${CMAKE_SOURCE_DIR}/src/daemon/UserSession.cpp
)

add_executable(ddm-helper ${HELPER_SOURCES})

target_link_libraries(ddm-helper
    PRIVATE
        common
        Qt6::Core
        PkgConfig::Pam
)

target_include_directories(ddm-helper PRIVATE
    ${CMAKE_SOURCE_DIR}/src/daemon
)

install(TARGETS ddm-helper DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}")
