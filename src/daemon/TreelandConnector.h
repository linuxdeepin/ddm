// Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include <QObject>

class QSocketNotifier;
class QTimer;

struct wl_display;
struct wl_callback;
struct treeland_ddm_v2;

namespace DDM {
    class Display;

    class TreelandConnector : public QObject {
        Q_OBJECT
    public:
        TreelandConnector(Display *display);
        ~TreelandConnector();

        /**
         * @brief Connect to treeland.
         *
         * Continuously tries until success.
         *
         * This should be called by Display when starting.
         */
        void connect();

        /**
         * @brief Disconnect from treeland.
         *
         * This should be called by Display when stopping.
         */
        void disconnect();

        ///////////////////////////////////////////////////////////
        // Request wrappers                                      //
        // Call them once you want to send something to treeland //
        // Documentations are available in treeland-ddm-v2.xml   //
        ///////////////////////////////////////////////////////////

        void capabilities(uint32_t capabilities) const;
        void userLoggedIn(const QString &username, const QString &session) const;
        void authenticationFailed(uint32_t error) const;
        void switchToGreeter() const;
        void switchToUser(const QString &username) const;
        void activateSession() const;
        void deactivateSession() const;
        void enableRender() const;
        struct wl_callback *disableRender() const;

        /** The proxy object for sending requests. Mainly for private use. */
        struct treeland_ddm_v2 *proxy{ nullptr };

    private Q_SLOTS:
        void tryConnect();
        void connected();

    private:
        struct wl_display *m_display{ nullptr };
        QSocketNotifier *m_notifier{ nullptr };
        QTimer *m_connectTimer{ nullptr };
    };
} // namespace DDM
