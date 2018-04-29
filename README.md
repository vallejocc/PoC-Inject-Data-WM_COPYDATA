# PoC-Inject-Data-WM_COPYDATA

A tiny PoC to inject and execute code into explorer.exe with WM_SETTEXT+WM_COPYDATA+SetThreadContext

    PoC code: Inject Explorer.exe process.
    
    APIs used: SendMessage(WM_SETTEXT), SendMessage(WM_COPYDATA), SetThreadContext, OpenProcess, VirtualQueryEx, SuspendThread, ResumeThread, Toolhelp apis.

    This code uses WM_SETTEXT and WM_COPYDATA messages to cause our controlled data to be copied into target process address space.

    In this way, we introduce a very simple ROP to launch notepad with CreateProcess("notepad.exe") and call ExitProcess later.

    We use SetThreadContext to redirect the thread.

    Tests done on platform:

    Windows 10 Pro 64 bits, version 1709 (OS comp. 16299.125).

    Ntdll version 10.0.16299.64.
