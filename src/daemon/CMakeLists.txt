configure_file(config.h.in config.h IMMEDIATE @ONLY)
set(DAEMON_SOURCES
    Auth.cpp
    DaemonApp.cpp
    DdeSeatdControl.cpp
    Display.cpp
    DisplayManager.cpp
    PowerManager.cpp
    SeatManager.cpp
    SocketServer.cpp
    TreelandConnector.cpp
    UserSession.cpp
    XorgDisplayServer.cpp
    TreelandDisplayServer.cpp
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
qt_add_repc_sources(ddm
    ${CMAKE_CURRENT_SOURCE_DIR}/ddmremote.rep
)
qt_add_repc_replicas(ddm
    ${CMAKE_CURRENT_SOURCE_DIR}/treelandremote.rep
)
target_link_libraries(ddm
    PRIVATE
        common
    PUBLIC
        Qt6::DBus
        Qt6::Network
        Qt6::RemoteObjects
        PkgConfig::Pam
        PkgConfig::LibSystemd
)

install(TARGETS ddm DESTINATION "${CMAKE_INSTALL_BINDIR}")
