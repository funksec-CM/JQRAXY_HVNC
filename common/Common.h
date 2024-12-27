#pragma once
#define SECURITY_WIN32
#pragma warning(disable: 4267)
#pragma warning(disable: 4244)
#pragma warning(disable: 4533)
#include <WinSock.h>
#include <Windows.h>
#include <Stdio.h>
#include <Security.h>
#include <Sddl.h>
#include <Shlwapi.h>
#include <Shlobj.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Wininet.h>
#include <Urlmon.h>



#define HOST (char*)"127.0.0.1"
#define PATH "/panel/client.php"
#define PORT 80
#define POLL 60000