install(FILES
    "org.freedesktop.DisplayManager.conf"
    DESTINATION "${DBUS_CONFIG_DIR}"
    RENAME ${DBUS_CONFIG_FILENAME}
)

install(FILES
    "org.deepin.DisplayManager.conf"
    DESTINATION "${DBUS_CONFIG_DIR}"
)

# DConfig schemas (see DDM_DCONFIG_APP_ID)

configure_file(
    "dconfig/org.deepin.dde.ddm.json.in"
    "${CMAKE_CURRENT_BINARY_DIR}/dconfig/${DDM_DCONFIG_APP_ID}.json"
    @ONLY
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/dconfig/${DDM_DCONFIG_APP_ID}.json"
    DESTINATION "${DDM_DCONFIG_DIR}"
)

install(FILES
    "dconfig/org.deepin.dde.ddm.state.json"
    DESTINATION "${DDM_DCONFIG_DIR}"
    RENAME "${DDM_DCONFIG_APP_ID}.state.json"
)

install(FILES
    "scripts/Xsession"
    "scripts/Xsetup"
    "scripts/Xstop"
    "scripts/wayland-session"
    DESTINATION "${DATA_INSTALL_DIR}/scripts"
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)

if(BUILD_MAN_PAGES)
    add_subdirectory(man)
endif()
