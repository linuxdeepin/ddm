// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "ForkExitGuard.h"

#include <QCoreApplication>
#include <QProcess>
#include <QProcessEnvironment>
#include <QString>
#include <QtTest>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace DDM;

namespace {
    constexpr char selfTestEnv[] = "DDM_FORKEXITGUARD_SELFTEST";

    // Canary exit handler used to verify which handlers get to run before
    // ForkExitGuard bypasses them. When armed, it writes one byte into a
    // pipe watched by the test process; an armed write from a forked child
    // means the inherited handler was NOT bypassed.
    int s_canaryFd = -1;
    bool s_canaryArmed = false;

    void canaryExitHandler() {
        if (s_canaryArmed && s_canaryFd >= 0) {
            const char marker = 'C';
            const ssize_t written = ::write(s_canaryFd, &marker, 1);
            Q_UNUSED(written);
        }
    }

    // Disarm the canary and forget its pipe write end (parent side only).
    void disarmCanary() {
        s_canaryArmed = false;
        s_canaryFd = -1;
    }

    int waitChild(pid_t pid) {
        int status = -1;
        while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) { }
        return status;
    }

    // Run this test binary again as a helper process in the given self-test
    // mode and return it via outProc (already finished).
    bool runSelfTest(const char *mode, QProcess &outProc) {
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert(QLatin1String(selfTestEnv), QLatin1String(mode));
        outProc.setProcessEnvironment(env);
        outProc.setProgram(QCoreApplication::applicationFilePath());
        outProc.start();
        if (!outProc.waitForStarted(5000))
            return false;
        return outProc.waitForFinished(10000);
    }
}

class TestForkExitGuard : public QObject {
    Q_OBJECT
private Q_SLOTS:
    void testInitialState();
    void testInstall();
    void testHandlerIsNoOpInOwnerProcess();
    void testHandlerExitsInForkedChild();
    void testChildExitBypassesOlderHandlers();
    void testReinstallSupersedesNewerHandlers();
    void testOwnerExitPreservesNormalCleanup();
    void testDescendantExitIsBypassed();
    void testHandlerNoOpInOwnerSubprocess();
};

void TestForkExitGuard::testInitialState()
{
    // Must run first: a fresh process image has no guard installed yet.
    QVERIFY(!ForkExitGuard::isInstalled());
    QCOMPARE(ForkExitGuard::ownerPid(), static_cast<pid_t>(-1));
}

void TestForkExitGuard::testInstall()
{
    QVERIFY(ForkExitGuard::install());
    QVERIFY(ForkExitGuard::isInstalled());
    QCOMPARE(ForkExitGuard::ownerPid(), getpid());

    // Installing again refreshes the registration (moves the handler to the
    // end of the LIFO list) and must keep the owner PID unchanged.
    QVERIFY(ForkExitGuard::install());
    QVERIFY(ForkExitGuard::isInstalled());
    QCOMPARE(ForkExitGuard::ownerPid(), getpid());
}

void TestForkExitGuard::testHandlerIsNoOpInOwnerProcess()
{
    // In the owner process the handler must simply return, so the regular
    // exit cleanup keeps running. If it wrongly _exit()ed, this test process
    // would die here; testHandlerNoOpInOwnerSubprocess pins that case down
    // from the outside.
    QVERIFY(ForkExitGuard::isInstalled());
    ForkExitGuard::bypassInheritedCleanup();
    QVERIFY(ForkExitGuard::isInstalled());
}

void TestForkExitGuard::testHandlerExitsInForkedChild()
{
    QVERIFY(ForkExitGuard::isInstalled());

    const pid_t pid = fork();
    QVERIFY(pid >= 0);
    if (pid == 0) {
        // Child: our PID differs from the recorded owner, so the handler
        // must terminate us immediately with status 0.
        ForkExitGuard::bypassInheritedCleanup();
        // Only reached if the handler wrongly returned.
        _exit(123);
    }

    const int status = waitChild(pid);
    QVERIFY(WIFEXITED(status));
    QCOMPARE(WEXITSTATUS(status), 0);
}

void TestForkExitGuard::testChildExitBypassesOlderHandlers()
{
    int pipeFd[2];
    QCOMPARE(pipe(pipeFd), 0);

    // Register the canary BEFORE installing the guard: it models daemon-era
    // handlers (e.g. Qt static cleanup) registered before fork(). The guard
    // is then the newest handler and must run first (LIFO) in the child.
    s_canaryFd = pipeFd[1];
    s_canaryArmed = true;
    QCOMPARE(atexit(canaryExitHandler), 0);
    QVERIFY(ForkExitGuard::install());

    const pid_t pid = fork();
    QVERIFY(pid >= 0);
    if (pid == 0) {
        close(pipeFd[0]);
        ::exit(42);
    }
    close(pipeFd[1]);
    disarmCanary();

    const int status = waitChild(pid);
    QVERIFY(WIFEXITED(status));
    // The guard flattened exit(42) into _exit(0).
    QCOMPARE(WEXITSTATUS(status), 0);

    // The canary must not have run in the child, i.e. nothing was written.
    struct pollfd pfd {};
    pfd.fd = pipeFd[0];
    pfd.events = POLLIN;
    QCOMPARE(poll(&pfd, 1, 0), 0);
    close(pipeFd[0]);
}

void TestForkExitGuard::testReinstallSupersedesNewerHandlers()
{
    int pipeFd[2];
    QCOMPARE(pipe(pipeFd), 0);

    // Register the canary AFTER the previous install(), then install()
    // again: handlers registered between two fork()s must also be bypassed
    // in children, because the refreshed registration runs first (LIFO).
    s_canaryFd = pipeFd[1];
    s_canaryArmed = true;
    QCOMPARE(atexit(canaryExitHandler), 0);
    QVERIFY(ForkExitGuard::install());

    const pid_t pid = fork();
    QVERIFY(pid >= 0);
    if (pid == 0) {
        close(pipeFd[0]);
        ::exit(7);
    }
    close(pipeFd[1]);
    disarmCanary();

    const int status = waitChild(pid);
    QVERIFY(WIFEXITED(status));
    QCOMPARE(WEXITSTATUS(status), 0);

    struct pollfd pfd {};
    pfd.fd = pipeFd[0];
    pfd.events = POLLIN;
    QCOMPARE(poll(&pfd, 1, 0), 0);
    close(pipeFd[0]);
}

void TestForkExitGuard::testOwnerExitPreservesNormalCleanup()
{
    // Subprocess: installs the guard, registers a canary and exit(7)s.
    // The owner process must keep its regular cleanup (canary runs) and
    // its exit code (the guard must not fire for the owner).
    QProcess proc;
    QVERIFY(runSelfTest("owner-exit", proc));
    QCOMPARE(proc.exitStatus(), QProcess::NormalExit);
    QCOMPARE(proc.exitCode(), 7);
    QVERIFY(QString::fromLocal8Bit(proc.readAllStandardOutput()).contains(QStringLiteral("CANARY")));
}

void TestForkExitGuard::testDescendantExitIsBypassed()
{
    // Subprocess: installs the guard, forks, and the child exit(9)s.
    // The child inherits the guard, so it must exit with status 0 without
    // running any inherited cleanup; the harness prints the child's code.
    QProcess proc;
    QVERIFY(runSelfTest("descendant-exit", proc));
    QCOMPARE(proc.exitStatus(), QProcess::NormalExit);
    QCOMPARE(proc.exitCode(), 0);
    QCOMPARE(QString::fromLocal8Bit(proc.readAllStandardOutput()).trimmed(), QStringLiteral("0"));
}

void TestForkExitGuard::testHandlerNoOpInOwnerSubprocess()
{
    // Subprocess: installs the guard and calls the handler directly.
    // A wrongly firing guard would kill the harness silently with status 0,
    // so success is proven by the SURVIVED marker on stdout.
    QProcess proc;
    QVERIFY(runSelfTest("owner-noop", proc));
    QCOMPARE(proc.exitStatus(), QProcess::NormalExit);
    QCOMPARE(proc.exitCode(), 0);
    QVERIFY(QString::fromLocal8Bit(proc.readAllStandardOutput()).contains(QStringLiteral("SURVIVED")));
}

int main(int argc, char *argv[])
{
    const QByteArray selfTest = qgetenv(selfTestEnv);

    if (selfTest == "owner-noop") {
        if (!ForkExitGuard::install())
            return 1;
        // Must return instead of terminating the process.
        ForkExitGuard::bypassInheritedCleanup();
        puts("SURVIVED");
        return 0;
    }

    if (selfTest == "owner-exit") {
        // Registered before the guard, so it runs after the guard (LIFO):
        // reaching it proves the guard did not fire for the owner.
        atexit([]() {
            puts("CANARY");
        });
        if (!ForkExitGuard::install())
            return 1;
        ::exit(7);
    }

    if (selfTest == "descendant-exit") {
        if (!ForkExitGuard::install())
            return 1;
        const pid_t pid = fork();
        if (pid == 0)
            ::exit(9);
        if (pid < 0)
            return 1;
        int status = -1;
        while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) { }
        if (!WIFEXITED(status))
            return 1;
        printf("%d\n", WEXITSTATUS(status));
        return 0;
    }

    QCoreApplication app(argc, argv);
    TestForkExitGuard tc;
    return QTest::qExec(&tc, argc, argv);
}

#include "tst_forkexitguard.moc"
