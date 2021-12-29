#pragma once

#include "ImpersonateToken\utils.h"
#include "ImpersonateToken\utils.cpp"
_Success_(return)
BOOL FindProcessTokenAndDuplicate(_In_ LPCWSTR pwszTargetSid, _Out_ PHANDLE phToken, _In_opt_ LPCWSTR pwszPrivileges[], _In_ DWORD dwPrivilegeCount)
{
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
	BOOL bReturnValue = FALSE;

	PSID pTargetSid = NULL;
	PVOID pBuffer = NULL;
	PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
	HANDLE hProcess = NULL, hToken = NULL, hTokenDup = NULL;
	DWORD dwReturnedLen = 0, dwBufSize = 0x1000, dwSessionId = 0;
	PSID pSidTmp = NULL;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;

	LPWSTR pwszUsername = NULL;

	if (!ConvertStringSidToSid(pwszTargetSid, &pTargetSid))
		goto end;

	while (TRUE)
	{
		pBuffer = LocalAlloc(LPTR, dwBufSize);
		if (!pBuffer || status != STATUS_INFO_LENGTH_MISMATCH)
			break;

		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, pBuffer, dwBufSize, &dwReturnedLen);
		if (NT_SUCCESS(status))
		{
			pProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
			while (TRUE) {
				if (hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PtrToUlong(pProcInfo->UniqueProcessId)))
				{
					if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
					{
						if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hTokenDup))
						{
							if (TokenGetSid(hTokenDup, &pSidTmp) && TokenGetUsername(hTokenDup, &pwszUsername))
							{
								if (TokenCompareSids(pSidTmp, pTargetSid))
								{
									PrintDebug(L"Found a potential Process candidate: PID=%d - Image='%ws' - User='%ws'\n", PtrToUlong(pProcInfo->UniqueProcessId), pProcInfo->ImageName.Buffer, pwszUsername);

									BOOL bTokenIsNotRestricted = FALSE;
									TokenIsNotRestricted(hTokenDup, &bTokenIsNotRestricted);

									if (bTokenIsNotRestricted)
										PrintDebug(L"This token is not restricted.\n");
									else
										PrintDebug(L"This token is restricted.\n");

									if (bTokenIsNotRestricted)
									{
										if (pwszPrivileges && dwPrivilegeCount != 0)
										{
											DWORD dwPrivilegeFound = 0;
											for (DWORD i = 0; i < dwPrivilegeCount; i++)
											{
												if (TokenCheckPrivilege(hTokenDup, pwszPrivileges[i], FALSE))
													dwPrivilegeFound++;
											}

											PrintDebug(L"Found %d/%d required privileges in token.\n", dwPrivilegeFound, dwPrivilegeCount);

											if (dwPrivilegeFound == dwPrivilegeCount)
											{
												PrintDebug(L"Found a valid Token candidate.\n");

												*phToken = hTokenDup;
												bReturnValue = TRUE;
											}
										}
										else
										{
											PrintDebug(L"Found a valid Token.\n");

											*phToken = hTokenDup;
											bReturnValue = TRUE;
										}
									}
								}
								LocalFree(pSidTmp);
								LocalFree(pwszUsername);
							}
							if (!bReturnValue)
								CloseHandle(hTokenDup);
						}
						CloseHandle(hToken);
					}
					CloseHandle(hProcess);
				}

				// If we found a valid token, stop
				if (bReturnValue)
					break;

				// If next entry is null, stop
				if (!pProcInfo->NextEntryOffset)
					break;

				// Increment SYSTEM_PROCESS_INFORMATION pointer
				pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
			}
		}

		LocalFree(pBuffer);
		dwBufSize <<= 1;
	}

end:
	if (pTargetSid)
		LocalFree(pTargetSid);

	return bReturnValue;
}

_Success_(return)
BOOL Impersonate(_In_ HANDLE hToken)
{
	HANDLE hThread = GetCurrentThread(); // Pseudo handle, does not need to be closed

	if (!SetThreadToken(&hThread, hToken))
	{
		PrintLastError(L"SetThreadToken");
		return FALSE;
	}

	return TRUE;
}

_Success_(return)
BOOL ImpersonateUser(_In_ LPCWSTR pwszSid, _Out_ PHANDLE phToken, _In_opt_ LPCWSTR pwszPrivileges[], _In_ DWORD dwPrivilegeCount)
{
	BOOL bReturnValue = FALSE;

	HANDLE hCurrentProcessToken = NULL;
	HANDLE hToken = NULL;
	HANDLE hCurrentThread = NULL;

	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hCurrentProcessToken))
	{
		PrintLastError(L"OpenProcessToken");
		goto end;
	}

	if (!TokenCheckPrivilege(hCurrentProcessToken, SE_DEBUG_NAME, TRUE))
		goto end;

	if (!TokenCheckPrivilege(hCurrentProcessToken, SE_IMPERSONATE_NAME, TRUE))
		goto end;

	if (!FindProcessTokenAndDuplicate(pwszSid, &hToken, pwszPrivileges, dwPrivilegeCount))
		goto end;

	if (!Impersonate(hToken))
		goto end;

	*phToken = hToken;
	bReturnValue = TRUE;

end:
	if (hCurrentProcessToken)
		CloseHandle(hCurrentProcessToken);

	return bReturnValue;
}
_Success_(return)
BOOL ImpersonateSystem(_Out_ PHANDLE phSystemToken)
{
	LPCWSTR pwszPrivileges[2] = { SE_DEBUG_NAME, SE_ASSIGNPRIMARYTOKEN_NAME };

	return ImpersonateUser(L"S-1-5-18", phSystemToken, pwszPrivileges, sizeof(pwszPrivileges) / sizeof(*pwszPrivileges));
}

