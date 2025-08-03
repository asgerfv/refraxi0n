#include "stdafx.h"
#include <Windows.h>
#include <cstdint>


// ----------------------------------------------------------------------------


typedef void* (FourFunctions_t)[4];
//typedef uint32_t(*InternetOpenA_t)(LPCSTR lpszAgent, DWORD  dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD  dwFlags);
//typedef BOOL(*HttpSendRequestExW_t)(uint32_t hRequest, void* lpBuffersIn, void* lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL (WINAPI *IsDebuggerPresent_t)();
typedef VOID (WINAPI *OutputDebugStringA_t)(LPCSTR lpOutputString);


// ----------------------------------------------------------------------------


volatile FourFunctions_t g_wininetFunctions = {0};
volatile uint32_t g_dummy = 0;
volatile FourFunctions_t g_kernel32Functions = { 0 };
volatile FourFunctions_t g_ntdllFunctions = { 0 };

volatile FourFunctions_t* g_pWininetFunctions = nullptr;
volatile FourFunctions_t* g_pKernel32Functions = nullptr;
volatile FourFunctions_t* g_pNtdllFunctions = nullptr;

volatile OutputDebugStringA_t g_pOutputDebugStringA = nullptr;


// ----------------------------------------------------------------------------


__declspec(noinline) void UseRegularFunction()
{
	OutputDebugStringA("UseRegularFunction\n");
}


__declspec(noinline) void UseFunctionPointerFromIAT()
{
	(*g_pOutputDebugStringA)("UseFunctionPointerFromIAT\n");
}


__declspec(noinline) void UseFunctionPointerFromPointerToIAT()
{
	OutputDebugStringA_t pOutputDebugStringA = (OutputDebugStringA_t)( (*g_pKernel32Functions)[1]);
	(*pOutputDebugStringA)("UseFunctionPointerFromPointerToIAT\n");

	IsDebuggerPresent_t pIsDebuggerPresent_t = (IsDebuggerPresent_t)( (*g_pKernel32Functions)[0]);
	(*pIsDebuggerPresent_t)();
}


// ----------------------------------------------------------------------------


int _tmain(int argc, _TCHAR* argv[])
{
	HMODULE hWinInet = LoadLibraryA("wininet");
	g_wininetFunctions[0] = GetProcAddress(hWinInet, "InternetOpenA");
	g_wininetFunctions[1] = GetProcAddress(hWinInet, "InternetReadFileExA");
	g_wininetFunctions[2] = GetProcAddress(hWinInet, "InternetGoOnline");
	g_wininetFunctions[3] = GetProcAddress(hWinInet, "HttpSendRequestExW");
	g_pWininetFunctions = &g_wininetFunctions;

	g_dummy = 0xBAADC0DE + (uint32_t)hWinInet;

	HMODULE hNtDll = LoadLibraryA("ntdll");
	g_ntdllFunctions[0] = GetProcAddress(hNtDll, "NtOpenFile");
	g_ntdllFunctions[1] = GetProcAddress(hNtDll, "NtCreateFile");
	g_ntdllFunctions[2] = GetProcAddress(hNtDll, "NtClose");
	g_ntdllFunctions[3] = GetProcAddress(hNtDll, "ZwFlushBuffersFile");
	g_pNtdllFunctions = &g_ntdllFunctions;

	HMODULE nKernel32Dll = LoadLibraryA("kernel32");
	g_kernel32Functions[0] = GetProcAddress(nKernel32Dll, "IsDebuggerPresent");
	g_kernel32Functions[1] = GetProcAddress(nKernel32Dll, "OutputDebugStringA");
	g_pOutputDebugStringA = (OutputDebugStringA_t)g_kernel32Functions[1];
	g_pKernel32Functions = &g_kernel32Functions;

	UseRegularFunction();

	UseFunctionPointerFromIAT();

	UseFunctionPointerFromPointerToIAT();

	return 0;
}
