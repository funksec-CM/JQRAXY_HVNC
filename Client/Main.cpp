#include "StartDesktop.h"
#include <Windows.h>

#define WAIT_PERIOD INFINITE

void LaunchAndWait(const char* server, int prt) {
    HANDLE thr = StartDesktop(server, prt);
    if (thr == nullptr) {
        MessageBoxA(nullptr, "Error: Unable to initiate session.", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    WaitForSingleObject(thr, WAIT_PERIOD);
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char* srv = "127.0.0.1";
    const int prt = strtol("4444", nullptr, 10);
    LaunchAndWait(srv, prt);
    return 0;
}
