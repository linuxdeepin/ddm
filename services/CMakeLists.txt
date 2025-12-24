configure_file(ddm.service.in ddm.service)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ddm.service" DESTINATION "${SYSTEMD_SYSTEM_UNIT_DIR}")

configure_file(ddm-sysuser.conf.in ddm-sysuser.conf)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ddm-sysuser.conf" DESTINATION "${SYSTEMD_SYSUSERS_DIR}" RENAME dde.conf)

# systemd-tmpfiles can be used standalone without other systemd parts
if(DEFINED SYSTEMD_TMPFILES_DIR)
    configure_file(ddm-tmpfiles.conf.in ddm-tmpfiles.conf)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ddm-tmpfiles.conf" DESTINATION "${SYSTEMD_TMPFILES_DIR}" RENAME ddm.conf)
endif()

if(EXISTS "/etc/debian_version")
    install(FILES debian.ddm.pam DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/pam.d RENAME ddm)
else()
    install(FILES ddm.pam DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/pam.d RENAME ddm)
endif()
