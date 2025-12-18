include_directories(
    ${LIBXAU_INCLUDE_DIRS}
    "${LIBXCB_INCLUDE_DIR}"
)

pkg_search_module(WAYLAND REQUIRED IMPORTED_TARGET wayland-client)

# Generate treeland-ddm protocol files
set(TREELAND_DDM_HEADER ${CMAKE_CURRENT_BINARY_DIR}/treeland-ddm-v1.h)
set(TREELAND_DDM_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/treeland-ddm-v1.c)

add_custom_command(
    OUTPUT ${TREELAND_DDM_HEADER}
    COMMAND wayland-scanner client-header < ${TREELAND_PROTOCOLS_DATA_DIR}/treeland-ddm-v1.xml > ${TREELAND_DDM_HEADER}
    DEPENDS ${TREELAND_PROTOCOLS_DATA_DIR}/treeland-ddm-v1.xml
    COMMENT "Generating treeland-ddm-v1.h"
)

add_custom_command(
    OUTPUT ${TREELAND_DDM_SOURCE}
    COMMAND wayland-scanner private-code < ${TREELAND_PROTOCOLS_DATA_DIR}/treeland-ddm-v1.xml > ${TREELAND_DDM_SOURCE}
    DEPENDS ${TREELAND_PROTOCOLS_DATA_DIR}/treeland-ddm-v1.xml
    COMMENT "Generating treeland-ddm-v1.c"
)

configure_file(config.h.in config.h IMMEDIATE @ONLY)
set(DAEMON_SOURCES
    Auth.cpp
    DaemonApp.cpp
    Display.cpp
    DisplayManager.cpp
    DisplayServer.cpp
    Greeter.cpp
    Pam.cpp
    PowerManager.cpp
    Seat.cpp
    SeatManager.cpp
    SocketServer.cpp
    TreelandConnector.cpp
    UserSession.cpp
    XorgDisplayServer.cpp
    XorgUserDisplayServer.cpp
    XorgUserDisplayServer.h
    WaylandDisplayServer.cpp
    WaylandDisplayServer.h
    SingleWaylandDisplayServer.h
    SingleWaylandDisplayServer.cpp
    ${TREELAND_DDM_SOURCE}
)

qt_add_dbus_adaptor(DAEMON_SOURCES "${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.DisplayManager.xml"          "DisplayManager.h" DDM::DisplayManager)
qt_add_dbus_adaptor(DAEMON_SOURCES "${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.DisplayManager.Seat.xml"     "DisplayManager.h" DDM::DisplayManagerSeat)
qt_add_dbus_adaptor(DAEMON_SOURCES "${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.DisplayManager.Session.xml"  "DisplayManager.h" DDM::DisplayManagerSession)
qt_add_dbus_adaptor(DAEMON_SOURCES "${CMAKE_SOURCE_DIR}/data/interfaces/org.deepin.DisplayManager.xml"  "DisplayManager.h" DDM::DisplayManager dbus_ddm_displaymanager DDMDisplayManagerAdaptor)

set_source_files_properties("${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.login1.Manager.xml" PROPERTIES
   INCLUDE "LogindDBusTypes.h"
)
set_source_files_properties("${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.login1.Seat.xml" PROPERTIES
   INCLUDE "LogindDBusTypes.h"
)

set_source_files_properties("${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.login1.Session.xml" PROPERTIES
   INCLUDE "LogindDBusTypes.h"
)

set_source_files_properties("${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.login1.User.xml" PROPERTIES
   INCLUDE "LogindDBusTypes.h"
)

qt_add_dbus_interface(DAEMON_SOURCES "${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.login1.Manager.xml"  "Login1Manager")
qt_add_dbus_interface(DAEMON_SOURCES "${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.login1.Seat.xml"  "Login1Seat")
qt_add_dbus_interface(DAEMON_SOURCES "${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.login1.Session.xml"  "Login1Session")
qt_add_dbus_interface(DAEMON_SOURCES "${CMAKE_SOURCE_DIR}/data/interfaces/org.freedesktop.login1.User.xml"  "Login1User")

add_executable(ddm ${DAEMON_SOURCES})
target_link_libraries(ddm
    PRIVATE
        common
    PUBLIC
        Qt${QT_MAJOR_VERSION}::DBus
        Qt${QT_MAJOR_VERSION}::Network
        Qt${QT_MAJOR_VERSION}::Qml
        ${LIBXCB_LIBRARIES}
        ${PAM_LIBRARIES}
        PkgConfig::WAYLAND
)

if(JOURNALD_FOUND)
    target_link_libraries(ddm
        PUBLIC
            ${JOURNALD_LIBRARIES}
    )
endif()

install(TARGETS ddm DESTINATION "${CMAKE_INSTALL_BINDIR}")
