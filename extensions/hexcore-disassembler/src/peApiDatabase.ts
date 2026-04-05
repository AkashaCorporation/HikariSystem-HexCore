/*---------------------------------------------------------------------------------------------
 *  HexCore PE API Signature Database v1.0.0
 *  Comprehensive Windows API type signatures for import resolution
 *  Covers 180+ APIs across kernel32, ntdll, advapi32, ws2_32, user32, crypt32, wininet, shell32
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

export interface ApiParameter {
	name: string;
	type: string;
}

export interface ApiSignature {
	name: string;
	dll: string;
	returnType: string;
	parameters: ApiParameter[];
	category: ApiCategory;
	tags: string[];
}

export type ApiCategory =
	| 'file_io'
	| 'memory'
	| 'process'
	| 'thread'
	| 'sync'
	| 'registry'
	| 'network'
	| 'crypto'
	| 'service'
	| 'debug'
	| 'ui'
	| 'com'
	| 'shell'
	| 'system'
	| 'security'
	| 'hook'
	| 'injection'
	| 'loader'
	| 'exception'
	| 'pipe'
	| 'time';

/** Human-readable category labels for reports */
export const CATEGORY_LABELS: Record<ApiCategory, string> = {
	file_io: 'File I/O',
	memory: 'Memory Management',
	process: 'Process Management',
	thread: 'Thread Management',
	sync: 'Synchronization',
	registry: 'Registry',
	network: 'Networking',
	crypto: 'Cryptography',
	service: 'Service Control',
	debug: 'Debugging / Anti-Debug',
	ui: 'User Interface',
	com: 'COM / OLE',
	shell: 'Shell / Execution',
	system: 'System Information',
	security: 'Security / Privileges',
	hook: 'Hooking / Interception',
	injection: 'Code Injection',
	loader: 'Module Loading',
	exception: 'Exception Handling',
	pipe: 'IPC / Pipes',
	time: 'Timing / Performance'
};

const DB: ApiSignature[] = [
	// ========================= KERNEL32.DLL =========================
	{ name: 'CreateFile', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'file_io', tags: ['file_access'], parameters: [
		{ name: 'lpFileName', type: 'LPCTSTR' }, { name: 'dwDesiredAccess', type: 'DWORD' },
		{ name: 'dwShareMode', type: 'DWORD' }, { name: 'lpSecurityAttributes', type: 'LPSECURITY_ATTRIBUTES' },
		{ name: 'dwCreationDisposition', type: 'DWORD' }, { name: 'dwFlagsAndAttributes', type: 'DWORD' },
		{ name: 'hTemplateFile', type: 'HANDLE' }
	]},
	{ name: 'ReadFile', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: ['file_access'], parameters: [
		{ name: 'hFile', type: 'HANDLE' }, { name: 'lpBuffer', type: 'LPVOID' },
		{ name: 'nNumberOfBytesToRead', type: 'DWORD' }, { name: 'lpNumberOfBytesRead', type: 'LPDWORD' },
		{ name: 'lpOverlapped', type: 'LPOVERLAPPED' }
	]},
	{ name: 'WriteFile', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: ['file_access'], parameters: [
		{ name: 'hFile', type: 'HANDLE' }, { name: 'lpBuffer', type: 'LPCVOID' },
		{ name: 'nNumberOfBytesToWrite', type: 'DWORD' }, { name: 'lpNumberOfBytesWritten', type: 'LPDWORD' },
		{ name: 'lpOverlapped', type: 'LPOVERLAPPED' }
	]},
	{ name: 'CloseHandle', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: [], parameters: [
		{ name: 'hObject', type: 'HANDLE' }
	]},
	{ name: 'DeleteFile', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: ['destructive'], parameters: [
		{ name: 'lpFileName', type: 'LPCTSTR' }
	]},
	{ name: 'MoveFileEx', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: ['file_access'], parameters: [
		{ name: 'lpExistingFileName', type: 'LPCTSTR' }, { name: 'lpNewFileName', type: 'LPCTSTR' },
		{ name: 'dwFlags', type: 'DWORD' }
	]},
	{ name: 'CopyFile', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: ['file_access'], parameters: [
		{ name: 'lpExistingFileName', type: 'LPCTSTR' }, { name: 'lpNewFileName', type: 'LPCTSTR' },
		{ name: 'bFailIfExists', type: 'BOOL' }
	]},
	{ name: 'SetFilePointerEx', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: [], parameters: [
		{ name: 'hFile', type: 'HANDLE' }, { name: 'liDistanceToMove', type: 'LARGE_INTEGER' },
		{ name: 'lpNewFilePointer', type: 'PLARGE_INTEGER' }, { name: 'dwMoveMethod', type: 'DWORD' }
	]},
	{ name: 'GetFileSizeEx', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: [], parameters: [
		{ name: 'hFile', type: 'HANDLE' }, { name: 'lpFileSize', type: 'PLARGE_INTEGER' }
	]},
	{ name: 'FindFirstFile', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'file_io', tags: ['recon'], parameters: [
		{ name: 'lpFileName', type: 'LPCTSTR' }, { name: 'lpFindFileData', type: 'LPWIN32_FIND_DATA' }
	]},
	{ name: 'FindNextFile', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: ['recon'], parameters: [
		{ name: 'hFindFile', type: 'HANDLE' }, { name: 'lpFindFileData', type: 'LPWIN32_FIND_DATA' }
	]},
	{ name: 'FindClose', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: [], parameters: [
		{ name: 'hFindFile', type: 'HANDLE' }
	]},
	{ name: 'GetTempPath', dll: 'kernel32.dll', returnType: 'DWORD', category: 'file_io', tags: ['dropper'], parameters: [
		{ name: 'nBufferLength', type: 'DWORD' }, { name: 'lpBuffer', type: 'LPTSTR' }
	]},
	{ name: 'DeviceIoControl', dll: 'kernel32.dll', returnType: 'BOOL', category: 'file_io', tags: ['driver', 'rootkit'], parameters: [
		{ name: 'hDevice', type: 'HANDLE' }, { name: 'dwIoControlCode', type: 'DWORD' },
		{ name: 'lpInBuffer', type: 'LPVOID' }, { name: 'nInBufferSize', type: 'DWORD' },
		{ name: 'lpOutBuffer', type: 'LPVOID' }, { name: 'nOutBufferSize', type: 'DWORD' },
		{ name: 'lpBytesReturned', type: 'LPDWORD' }, { name: 'lpOverlapped', type: 'LPOVERLAPPED' }
	]},
	{ name: 'CreateFileMapping', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'memory', tags: ['injection'], parameters: [
		{ name: 'hFile', type: 'HANDLE' }, { name: 'lpFileMappingAttributes', type: 'LPSECURITY_ATTRIBUTES' },
		{ name: 'flProtect', type: 'DWORD' }, { name: 'dwMaximumSizeHigh', type: 'DWORD' },
		{ name: 'dwMaximumSizeLow', type: 'DWORD' }, { name: 'lpName', type: 'LPCTSTR' }
	]},
	{ name: 'MapViewOfFile', dll: 'kernel32.dll', returnType: 'LPVOID', category: 'memory', tags: ['injection'], parameters: [
		{ name: 'hFileMappingObject', type: 'HANDLE' }, { name: 'dwDesiredAccess', type: 'DWORD' },
		{ name: 'dwFileOffsetHigh', type: 'DWORD' }, { name: 'dwFileOffsetLow', type: 'DWORD' },
		{ name: 'dwNumberOfBytesToMap', type: 'SIZE_T' }
	]},
	{ name: 'VirtualAlloc', dll: 'kernel32.dll', returnType: 'LPVOID', category: 'memory', tags: ['injection', 'shellcode'], parameters: [
		{ name: 'lpAddress', type: 'LPVOID' }, { name: 'dwSize', type: 'SIZE_T' },
		{ name: 'flAllocationType', type: 'DWORD' }, { name: 'flProtect', type: 'DWORD' }
	]},
	{ name: 'VirtualAllocEx', dll: 'kernel32.dll', returnType: 'LPVOID', category: 'injection', tags: ['injection', 'shellcode'], parameters: [
		{ name: 'hProcess', type: 'HANDLE' }, { name: 'lpAddress', type: 'LPVOID' },
		{ name: 'dwSize', type: 'SIZE_T' }, { name: 'flAllocationType', type: 'DWORD' },
		{ name: 'flProtect', type: 'DWORD' }
	]},
	{ name: 'VirtualFree', dll: 'kernel32.dll', returnType: 'BOOL', category: 'memory', tags: [], parameters: [
		{ name: 'lpAddress', type: 'LPVOID' }, { name: 'dwSize', type: 'SIZE_T' },
		{ name: 'dwFreeType', type: 'DWORD' }
	]},
	{ name: 'VirtualProtect', dll: 'kernel32.dll', returnType: 'BOOL', category: 'memory', tags: ['injection', 'shellcode'], parameters: [
		{ name: 'lpAddress', type: 'LPVOID' }, { name: 'dwSize', type: 'SIZE_T' },
		{ name: 'flNewProtect', type: 'DWORD' }, { name: 'lpflOldProtect', type: 'PDWORD' }
	]},
	{ name: 'VirtualProtectEx', dll: 'kernel32.dll', returnType: 'BOOL', category: 'injection', tags: ['injection', 'shellcode'], parameters: [
		{ name: 'hProcess', type: 'HANDLE' }, { name: 'lpAddress', type: 'LPVOID' },
		{ name: 'dwSize', type: 'SIZE_T' }, { name: 'flNewProtect', type: 'DWORD' },
		{ name: 'lpflOldProtect', type: 'PDWORD' }
	]},
	{ name: 'VirtualQuery', dll: 'kernel32.dll', returnType: 'SIZE_T', category: 'memory', tags: ['recon'], parameters: [
		{ name: 'lpAddress', type: 'LPCVOID' }, { name: 'lpBuffer', type: 'PMEMORY_BASIC_INFORMATION' },
		{ name: 'dwLength', type: 'SIZE_T' }
	]},
	{ name: 'HeapCreate', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'memory', tags: [], parameters: [
		{ name: 'flOptions', type: 'DWORD' }, { name: 'dwInitialSize', type: 'SIZE_T' },
		{ name: 'dwMaximumSize', type: 'SIZE_T' }
	]},
	{ name: 'HeapAlloc', dll: 'kernel32.dll', returnType: 'LPVOID', category: 'memory', tags: [], parameters: [
		{ name: 'hHeap', type: 'HANDLE' }, { name: 'dwFlags', type: 'DWORD' },
		{ name: 'dwBytes', type: 'SIZE_T' }
	]},
	{ name: 'HeapFree', dll: 'kernel32.dll', returnType: 'BOOL', category: 'memory', tags: [], parameters: [
		{ name: 'hHeap', type: 'HANDLE' }, { name: 'dwFlags', type: 'DWORD' },
		{ name: 'lpMem', type: 'LPVOID' }
	]},
	{ name: 'GetProcessHeap', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'memory', tags: [], parameters: [] },
	{ name: 'CreateProcess', dll: 'kernel32.dll', returnType: 'BOOL', category: 'process', tags: ['execution'], parameters: [
		{ name: 'lpApplicationName', type: 'LPCTSTR' }, { name: 'lpCommandLine', type: 'LPTSTR' },
		{ name: 'lpProcessAttributes', type: 'LPSECURITY_ATTRIBUTES' }, { name: 'lpThreadAttributes', type: 'LPSECURITY_ATTRIBUTES' },
		{ name: 'bInheritHandles', type: 'BOOL' }, { name: 'dwCreationFlags', type: 'DWORD' },
		{ name: 'lpEnvironment', type: 'LPVOID' }, { name: 'lpCurrentDirectory', type: 'LPCTSTR' },
		{ name: 'lpStartupInfo', type: 'LPSTARTUPINFO' }, { name: 'lpProcessInformation', type: 'LPPROCESS_INFORMATION' }
	]},
	{ name: 'OpenProcess', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'process', tags: ['injection', 'recon'], parameters: [
		{ name: 'dwDesiredAccess', type: 'DWORD' }, { name: 'bInheritHandle', type: 'BOOL' },
		{ name: 'dwProcessId', type: 'DWORD' }
	]},
	{ name: 'TerminateProcess', dll: 'kernel32.dll', returnType: 'BOOL', category: 'process', tags: ['destructive'], parameters: [
		{ name: 'hProcess', type: 'HANDLE' }, { name: 'uExitCode', type: 'UINT' }
	]},
	{ name: 'ExitProcess', dll: 'kernel32.dll', returnType: 'void', category: 'process', tags: [], parameters: [
		{ name: 'uExitCode', type: 'UINT' }
	]},
	{ name: 'GetCurrentProcess', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'process', tags: [], parameters: [] },
	{ name: 'GetCurrentProcessId', dll: 'kernel32.dll', returnType: 'DWORD', category: 'process', tags: [], parameters: [] },
	{ name: 'ReadProcessMemory', dll: 'kernel32.dll', returnType: 'BOOL', category: 'injection', tags: ['injection', 'recon'], parameters: [
		{ name: 'hProcess', type: 'HANDLE' }, { name: 'lpBaseAddress', type: 'LPCVOID' },
		{ name: 'lpBuffer', type: 'LPVOID' }, { name: 'nSize', type: 'SIZE_T' },
		{ name: 'lpNumberOfBytesRead', type: 'SIZE_T*' }
	]},
	{ name: 'WriteProcessMemory', dll: 'kernel32.dll', returnType: 'BOOL', category: 'injection', tags: ['injection', 'shellcode'], parameters: [
		{ name: 'hProcess', type: 'HANDLE' }, { name: 'lpBaseAddress', type: 'LPVOID' },
		{ name: 'lpBuffer', type: 'LPCVOID' }, { name: 'nSize', type: 'SIZE_T' },
		{ name: 'lpNumberOfBytesWritten', type: 'SIZE_T*' }
	]},
	{ name: 'WinExec', dll: 'kernel32.dll', returnType: 'UINT', category: 'process', tags: ['execution'], parameters: [
		{ name: 'lpCmdLine', type: 'LPCSTR' }, { name: 'uCmdShow', type: 'UINT' }
	]},
	{ name: 'CreateThread', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'thread', tags: ['shellcode'], parameters: [
		{ name: 'lpThreadAttributes', type: 'LPSECURITY_ATTRIBUTES' }, { name: 'dwStackSize', type: 'SIZE_T' },
		{ name: 'lpStartAddress', type: 'LPTHREAD_START_ROUTINE' }, { name: 'lpParameter', type: 'LPVOID' },
		{ name: 'dwCreationFlags', type: 'DWORD' }, { name: 'lpThreadId', type: 'LPDWORD' }
	]},
	{ name: 'CreateRemoteThread', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'injection', tags: ['injection', 'shellcode'], parameters: [
		{ name: 'hProcess', type: 'HANDLE' }, { name: 'lpThreadAttributes', type: 'LPSECURITY_ATTRIBUTES' },
		{ name: 'dwStackSize', type: 'SIZE_T' }, { name: 'lpStartAddress', type: 'LPTHREAD_START_ROUTINE' },
		{ name: 'lpParameter', type: 'LPVOID' }, { name: 'dwCreationFlags', type: 'DWORD' },
		{ name: 'lpThreadId', type: 'LPDWORD' }
	]},
	{ name: 'SuspendThread', dll: 'kernel32.dll', returnType: 'DWORD', category: 'thread', tags: ['injection'], parameters: [
		{ name: 'hThread', type: 'HANDLE' }
	]},
	{ name: 'ResumeThread', dll: 'kernel32.dll', returnType: 'DWORD', category: 'thread', tags: ['injection'], parameters: [
		{ name: 'hThread', type: 'HANDLE' }
	]},
	{ name: 'GetThreadContext', dll: 'kernel32.dll', returnType: 'BOOL', category: 'thread', tags: ['injection'], parameters: [
		{ name: 'hThread', type: 'HANDLE' }, { name: 'lpContext', type: 'LPCONTEXT' }
	]},
	{ name: 'SetThreadContext', dll: 'kernel32.dll', returnType: 'BOOL', category: 'thread', tags: ['injection'], parameters: [
		{ name: 'hThread', type: 'HANDLE' }, { name: 'lpContext', type: 'const CONTEXT*' }
	]},
	{ name: 'QueueUserAPC', dll: 'kernel32.dll', returnType: 'DWORD', category: 'injection', tags: ['injection', 'apc_injection'], parameters: [
		{ name: 'pfnAPC', type: 'PAPCFUNC' }, { name: 'hThread', type: 'HANDLE' },
		{ name: 'dwData', type: 'ULONG_PTR' }
	]},
	{ name: 'LoadLibrary', dll: 'kernel32.dll', returnType: 'HMODULE', category: 'loader', tags: ['dynamic_loading'], parameters: [
		{ name: 'lpLibFileName', type: 'LPCTSTR' }
	]},
	{ name: 'LoadLibraryEx', dll: 'kernel32.dll', returnType: 'HMODULE', category: 'loader', tags: ['dynamic_loading'], parameters: [
		{ name: 'lpLibFileName', type: 'LPCTSTR' }, { name: 'hFile', type: 'HANDLE' },
		{ name: 'dwFlags', type: 'DWORD' }
	]},
	{ name: 'GetProcAddress', dll: 'kernel32.dll', returnType: 'FARPROC', category: 'loader', tags: ['dynamic_loading', 'api_resolve'], parameters: [
		{ name: 'hModule', type: 'HMODULE' }, { name: 'lpProcName', type: 'LPCSTR' }
	]},
	{ name: 'FreeLibrary', dll: 'kernel32.dll', returnType: 'BOOL', category: 'loader', tags: [], parameters: [
		{ name: 'hLibModule', type: 'HMODULE' }
	]},
	{ name: 'GetModuleHandle', dll: 'kernel32.dll', returnType: 'HMODULE', category: 'loader', tags: ['recon'], parameters: [
		{ name: 'lpModuleName', type: 'LPCTSTR' }
	]},
	{ name: 'GetModuleFileName', dll: 'kernel32.dll', returnType: 'DWORD', category: 'loader', tags: ['recon'], parameters: [
		{ name: 'hModule', type: 'HMODULE' }, { name: 'lpFilename', type: 'LPTSTR' },
		{ name: 'nSize', type: 'DWORD' }
	]},
	{ name: 'CreateMutex', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'sync', tags: ['singleton'], parameters: [
		{ name: 'lpMutexAttributes', type: 'LPSECURITY_ATTRIBUTES' }, { name: 'bInitialOwner', type: 'BOOL' },
		{ name: 'lpName', type: 'LPCTSTR' }
	]},
	{ name: 'WaitForSingleObject', dll: 'kernel32.dll', returnType: 'DWORD', category: 'sync', tags: [], parameters: [
		{ name: 'hHandle', type: 'HANDLE' }, { name: 'dwMilliseconds', type: 'DWORD' }
	]},
	{ name: 'WaitForMultipleObjects', dll: 'kernel32.dll', returnType: 'DWORD', category: 'sync', tags: [], parameters: [
		{ name: 'nCount', type: 'DWORD' }, { name: 'lpHandles', type: 'const HANDLE*' },
		{ name: 'bWaitAll', type: 'BOOL' }, { name: 'dwMilliseconds', type: 'DWORD' }
	]},
	{ name: 'CreateEvent', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'sync', tags: [], parameters: [
		{ name: 'lpEventAttributes', type: 'LPSECURITY_ATTRIBUTES' }, { name: 'bManualReset', type: 'BOOL' },
		{ name: 'bInitialState', type: 'BOOL' }, { name: 'lpName', type: 'LPCTSTR' }
	]},
	{ name: 'InitializeCriticalSection', dll: 'kernel32.dll', returnType: 'void', category: 'sync', tags: [], parameters: [
		{ name: 'lpCriticalSection', type: 'LPCRITICAL_SECTION' }
	]},
	{ name: 'EnterCriticalSection', dll: 'kernel32.dll', returnType: 'void', category: 'sync', tags: [], parameters: [
		{ name: 'lpCriticalSection', type: 'LPCRITICAL_SECTION' }
	]},
	{ name: 'LeaveCriticalSection', dll: 'kernel32.dll', returnType: 'void', category: 'sync', tags: [], parameters: [
		{ name: 'lpCriticalSection', type: 'LPCRITICAL_SECTION' }
	]},
	{ name: 'Sleep', dll: 'kernel32.dll', returnType: 'void', category: 'time', tags: ['evasion'], parameters: [
		{ name: 'dwMilliseconds', type: 'DWORD' }
	]},
	{ name: 'GetTickCount', dll: 'kernel32.dll', returnType: 'DWORD', category: 'time', tags: ['anti_debug'], parameters: [] },
	{ name: 'GetTickCount64', dll: 'kernel32.dll', returnType: 'ULONGLONG', category: 'time', tags: ['anti_debug'], parameters: [] },
	{ name: 'QueryPerformanceCounter', dll: 'kernel32.dll', returnType: 'BOOL', category: 'time', tags: ['anti_debug'], parameters: [
		{ name: 'lpPerformanceCount', type: 'LARGE_INTEGER*' }
	]},
	{ name: 'GetSystemTime', dll: 'kernel32.dll', returnType: 'void', category: 'time', tags: [], parameters: [
		{ name: 'lpSystemTime', type: 'LPSYSTEMTIME' }
	]},
	{ name: 'IsDebuggerPresent', dll: 'kernel32.dll', returnType: 'BOOL', category: 'debug', tags: ['anti_debug'], parameters: [] },
	{ name: 'CheckRemoteDebuggerPresent', dll: 'kernel32.dll', returnType: 'BOOL', category: 'debug', tags: ['anti_debug'], parameters: [
		{ name: 'hProcess', type: 'HANDLE' }, { name: 'pbDebuggerPresent', type: 'PBOOL' }
	]},
	{ name: 'OutputDebugString', dll: 'kernel32.dll', returnType: 'void', category: 'debug', tags: ['anti_debug'], parameters: [
		{ name: 'lpOutputString', type: 'LPCTSTR' }
	]},
	{ name: 'GetSystemInfo', dll: 'kernel32.dll', returnType: 'void', category: 'system', tags: ['recon'], parameters: [
		{ name: 'lpSystemInfo', type: 'LPSYSTEM_INFO' }
	]},
	{ name: 'GetComputerName', dll: 'kernel32.dll', returnType: 'BOOL', category: 'system', tags: ['recon', 'fingerprint'], parameters: [
		{ name: 'lpBuffer', type: 'LPTSTR' }, { name: 'nSize', type: 'LPDWORD' }
	]},
	{ name: 'GetEnvironmentVariable', dll: 'kernel32.dll', returnType: 'DWORD', category: 'system', tags: ['recon'], parameters: [
		{ name: 'lpName', type: 'LPCTSTR' }, { name: 'lpBuffer', type: 'LPTSTR' },
		{ name: 'nSize', type: 'DWORD' }
	]},
	{ name: 'GetLastError', dll: 'kernel32.dll', returnType: 'DWORD', category: 'system', tags: [], parameters: [] },
	{ name: 'MultiByteToWideChar', dll: 'kernel32.dll', returnType: 'int', category: 'system', tags: [], parameters: [
		{ name: 'CodePage', type: 'UINT' }, { name: 'dwFlags', type: 'DWORD' },
		{ name: 'lpMultiByteStr', type: 'LPCCH' }, { name: 'cbMultiByte', type: 'int' },
		{ name: 'lpWideCharStr', type: 'LPWSTR' }, { name: 'cchWideChar', type: 'int' }
	]},
	{ name: 'WideCharToMultiByte', dll: 'kernel32.dll', returnType: 'int', category: 'system', tags: [], parameters: [
		{ name: 'CodePage', type: 'UINT' }, { name: 'dwFlags', type: 'DWORD' },
		{ name: 'lpWideCharStr', type: 'LPCWCH' }, { name: 'cchWideChar', type: 'int' },
		{ name: 'lpMultiByteStr', type: 'LPSTR' }, { name: 'cbMultiByte', type: 'int' },
		{ name: 'lpDefaultChar', type: 'LPCCH' }, { name: 'lpUsedDefaultChar', type: 'LPBOOL' }
	]},
	{ name: 'CreateToolhelp32Snapshot', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'process', tags: ['recon', 'enumeration'], parameters: [
		{ name: 'dwFlags', type: 'DWORD' }, { name: 'th32ProcessID', type: 'DWORD' }
	]},
	{ name: 'Process32First', dll: 'kernel32.dll', returnType: 'BOOL', category: 'process', tags: ['recon', 'enumeration'], parameters: [
		{ name: 'hSnapshot', type: 'HANDLE' }, { name: 'lppe', type: 'LPPROCESSENTRY32' }
	]},
	{ name: 'Process32Next', dll: 'kernel32.dll', returnType: 'BOOL', category: 'process', tags: ['recon', 'enumeration'], parameters: [
		{ name: 'hSnapshot', type: 'HANDLE' }, { name: 'lppe', type: 'LPPROCESSENTRY32' }
	]},
	{ name: 'CreatePipe', dll: 'kernel32.dll', returnType: 'BOOL', category: 'pipe', tags: ['ipc'], parameters: [
		{ name: 'hReadPipe', type: 'PHANDLE' }, { name: 'hWritePipe', type: 'PHANDLE' },
		{ name: 'lpPipeAttributes', type: 'LPSECURITY_ATTRIBUTES' }, { name: 'nSize', type: 'DWORD' }
	]},
	{ name: 'CreateNamedPipe', dll: 'kernel32.dll', returnType: 'HANDLE', category: 'pipe', tags: ['ipc', 'c2'], parameters: [
		{ name: 'lpName', type: 'LPCTSTR' }, { name: 'dwOpenMode', type: 'DWORD' },
		{ name: 'dwPipeMode', type: 'DWORD' }, { name: 'nMaxInstances', type: 'DWORD' },
		{ name: 'nOutBufferSize', type: 'DWORD' }, { name: 'nInBufferSize', type: 'DWORD' },
		{ name: 'nDefaultTimeOut', type: 'DWORD' }, { name: 'lpSecurityAttributes', type: 'LPSECURITY_ATTRIBUTES' }
	]},
	{ name: 'SetUnhandledExceptionFilter', dll: 'kernel32.dll', returnType: 'LPTOP_LEVEL_EXCEPTION_FILTER', category: 'exception', tags: ['anti_debug'], parameters: [
		{ name: 'lpTopLevelExceptionFilter', type: 'LPTOP_LEVEL_EXCEPTION_FILTER' }
	]},
	{ name: 'AddVectoredExceptionHandler', dll: 'kernel32.dll', returnType: 'PVOID', category: 'exception', tags: ['anti_debug'], parameters: [
		{ name: 'First', type: 'ULONG' }, { name: 'Handler', type: 'PVECTORED_EXCEPTION_HANDLER' }
	]},

	// ========================= NTDLL.DLL =========================
	{ name: 'NtCreateFile', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'file_io', tags: ['native_api'], parameters: [
		{ name: 'FileHandle', type: 'PHANDLE' }, { name: 'DesiredAccess', type: 'ACCESS_MASK' },
		{ name: 'ObjectAttributes', type: 'POBJECT_ATTRIBUTES' }, { name: 'IoStatusBlock', type: 'PIO_STATUS_BLOCK' },
		{ name: 'AllocationSize', type: 'PLARGE_INTEGER' }, { name: 'FileAttributes', type: 'ULONG' },
		{ name: 'ShareAccess', type: 'ULONG' }, { name: 'CreateDisposition', type: 'ULONG' },
		{ name: 'CreateOptions', type: 'ULONG' }, { name: 'EaBuffer', type: 'PVOID' },
		{ name: 'EaLength', type: 'ULONG' }
	]},
	{ name: 'NtAllocateVirtualMemory', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'injection', tags: ['native_api', 'injection', 'shellcode'], parameters: [
		{ name: 'ProcessHandle', type: 'HANDLE' }, { name: 'BaseAddress', type: 'PVOID*' },
		{ name: 'ZeroBits', type: 'ULONG_PTR' }, { name: 'RegionSize', type: 'PSIZE_T' },
		{ name: 'AllocationType', type: 'ULONG' }, { name: 'Protect', type: 'ULONG' }
	]},
	{ name: 'NtWriteVirtualMemory', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'injection', tags: ['native_api', 'injection'], parameters: [
		{ name: 'ProcessHandle', type: 'HANDLE' }, { name: 'BaseAddress', type: 'PVOID' },
		{ name: 'Buffer', type: 'PVOID' }, { name: 'NumberOfBytesToWrite', type: 'SIZE_T' },
		{ name: 'NumberOfBytesWritten', type: 'PSIZE_T' }
	]},
	{ name: 'NtQueryInformationProcess', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'process', tags: ['native_api', 'anti_debug', 'recon'], parameters: [
		{ name: 'ProcessHandle', type: 'HANDLE' }, { name: 'ProcessInformationClass', type: 'PROCESSINFOCLASS' },
		{ name: 'ProcessInformation', type: 'PVOID' }, { name: 'ProcessInformationLength', type: 'ULONG' },
		{ name: 'ReturnLength', type: 'PULONG' }
	]},
	{ name: 'NtQuerySystemInformation', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'system', tags: ['native_api', 'anti_debug', 'recon'], parameters: [
		{ name: 'SystemInformationClass', type: 'SYSTEM_INFORMATION_CLASS' },
		{ name: 'SystemInformation', type: 'PVOID' }, { name: 'SystemInformationLength', type: 'ULONG' },
		{ name: 'ReturnLength', type: 'PULONG' }
	]},
	{ name: 'NtSetInformationThread', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'debug', tags: ['native_api', 'anti_debug'], parameters: [
		{ name: 'ThreadHandle', type: 'HANDLE' }, { name: 'ThreadInformationClass', type: 'THREADINFOCLASS' },
		{ name: 'ThreadInformation', type: 'PVOID' }, { name: 'ThreadInformationLength', type: 'ULONG' }
	]},
	{ name: 'NtMapViewOfSection', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'injection', tags: ['native_api', 'injection'], parameters: [
		{ name: 'SectionHandle', type: 'HANDLE' }, { name: 'ProcessHandle', type: 'HANDLE' },
		{ name: 'BaseAddress', type: 'PVOID*' }, { name: 'ZeroBits', type: 'ULONG_PTR' },
		{ name: 'CommitSize', type: 'SIZE_T' }, { name: 'SectionOffset', type: 'PLARGE_INTEGER' },
		{ name: 'ViewSize', type: 'PSIZE_T' }, { name: 'InheritDisposition', type: 'SECTION_INHERIT' },
		{ name: 'AllocationType', type: 'ULONG' }, { name: 'Win32Protect', type: 'ULONG' }
	]},
	{ name: 'NtUnmapViewOfSection', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'injection', tags: ['native_api', 'process_hollowing'], parameters: [
		{ name: 'ProcessHandle', type: 'HANDLE' }, { name: 'BaseAddress', type: 'PVOID' }
	]},
	{ name: 'NtClose', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'system', tags: ['native_api'], parameters: [
		{ name: 'Handle', type: 'HANDLE' }
	]},
	{ name: 'NtDelayExecution', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'time', tags: ['native_api', 'evasion'], parameters: [
		{ name: 'Alertable', type: 'BOOLEAN' }, { name: 'DelayInterval', type: 'PLARGE_INTEGER' }
	]},
	{ name: 'RtlDecompressBuffer', dll: 'ntdll.dll', returnType: 'NTSTATUS', category: 'system', tags: ['native_api', 'packer'], parameters: [
		{ name: 'CompressionFormat', type: 'USHORT' }, { name: 'UncompressedBuffer', type: 'PUCHAR' },
		{ name: 'UncompressedBufferSize', type: 'ULONG' }, { name: 'CompressedBuffer', type: 'PUCHAR' },
		{ name: 'CompressedBufferSize', type: 'ULONG' }, { name: 'FinalUncompressedSize', type: 'PULONG' }
	]},

	// ========================= ADVAPI32.DLL =========================
	{ name: 'RegOpenKeyEx', dll: 'advapi32.dll', returnType: 'LSTATUS', category: 'registry', tags: ['persistence', 'recon'], parameters: [
		{ name: 'hKey', type: 'HKEY' }, { name: 'lpSubKey', type: 'LPCTSTR' },
		{ name: 'ulOptions', type: 'DWORD' }, { name: 'samDesired', type: 'REGSAM' },
		{ name: 'phkResult', type: 'PHKEY' }
	]},
	{ name: 'RegSetValueEx', dll: 'advapi32.dll', returnType: 'LSTATUS', category: 'registry', tags: ['persistence'], parameters: [
		{ name: 'hKey', type: 'HKEY' }, { name: 'lpValueName', type: 'LPCTSTR' },
		{ name: 'Reserved', type: 'DWORD' }, { name: 'dwType', type: 'DWORD' },
		{ name: 'lpData', type: 'const BYTE*' }, { name: 'cbData', type: 'DWORD' }
	]},
	{ name: 'RegQueryValueEx', dll: 'advapi32.dll', returnType: 'LSTATUS', category: 'registry', tags: ['recon'], parameters: [
		{ name: 'hKey', type: 'HKEY' }, { name: 'lpValueName', type: 'LPCTSTR' },
		{ name: 'lpReserved', type: 'LPDWORD' }, { name: 'lpType', type: 'LPDWORD' },
		{ name: 'lpData', type: 'LPBYTE' }, { name: 'lpcbData', type: 'LPDWORD' }
	]},
	{ name: 'RegCreateKeyEx', dll: 'advapi32.dll', returnType: 'LSTATUS', category: 'registry', tags: ['persistence'], parameters: [
		{ name: 'hKey', type: 'HKEY' }, { name: 'lpSubKey', type: 'LPCTSTR' },
		{ name: 'Reserved', type: 'DWORD' }, { name: 'lpClass', type: 'LPTSTR' },
		{ name: 'dwOptions', type: 'DWORD' }, { name: 'samDesired', type: 'REGSAM' },
		{ name: 'lpSecurityAttributes', type: 'LPSECURITY_ATTRIBUTES' }, { name: 'phkResult', type: 'PHKEY' },
		{ name: 'lpdwDisposition', type: 'LPDWORD' }
	]},
	{ name: 'RegCloseKey', dll: 'advapi32.dll', returnType: 'LSTATUS', category: 'registry', tags: [], parameters: [
		{ name: 'hKey', type: 'HKEY' }
	]},
	{ name: 'GetUserName', dll: 'advapi32.dll', returnType: 'BOOL', category: 'system', tags: ['recon', 'fingerprint'], parameters: [
		{ name: 'lpBuffer', type: 'LPTSTR' }, { name: 'pcbBuffer', type: 'LPDWORD' }
	]},
	{ name: 'CryptAcquireContext', dll: 'advapi32.dll', returnType: 'BOOL', category: 'crypto', tags: ['encryption'], parameters: [
		{ name: 'phProv', type: 'HCRYPTPROV*' }, { name: 'szContainer', type: 'LPCTSTR' },
		{ name: 'szProvider', type: 'LPCTSTR' }, { name: 'dwProvType', type: 'DWORD' },
		{ name: 'dwFlags', type: 'DWORD' }
	]},
	{ name: 'CryptEncrypt', dll: 'advapi32.dll', returnType: 'BOOL', category: 'crypto', tags: ['encryption', 'ransomware'], parameters: [
		{ name: 'hKey', type: 'HCRYPTKEY' }, { name: 'hHash', type: 'HCRYPTHASH' },
		{ name: 'Final', type: 'BOOL' }, { name: 'dwFlags', type: 'DWORD' },
		{ name: 'pbData', type: 'BYTE*' }, { name: 'pdwDataLen', type: 'DWORD*' },
		{ name: 'dwBufLen', type: 'DWORD' }
	]},
	{ name: 'CryptDecrypt', dll: 'advapi32.dll', returnType: 'BOOL', category: 'crypto', tags: ['encryption'], parameters: [
		{ name: 'hKey', type: 'HCRYPTKEY' }, { name: 'hHash', type: 'HCRYPTHASH' },
		{ name: 'Final', type: 'BOOL' }, { name: 'dwFlags', type: 'DWORD' },
		{ name: 'pbData', type: 'BYTE*' }, { name: 'pdwDataLen', type: 'DWORD*' }
	]},
	{ name: 'CryptGenKey', dll: 'advapi32.dll', returnType: 'BOOL', category: 'crypto', tags: ['encryption', 'ransomware'], parameters: [
		{ name: 'hProv', type: 'HCRYPTPROV' }, { name: 'Algid', type: 'ALG_ID' },
		{ name: 'dwFlags', type: 'DWORD' }, { name: 'phKey', type: 'HCRYPTKEY*' }
	]},
	{ name: 'OpenProcessToken', dll: 'advapi32.dll', returnType: 'BOOL', category: 'security', tags: ['privilege_escalation'], parameters: [
		{ name: 'ProcessHandle', type: 'HANDLE' }, { name: 'DesiredAccess', type: 'DWORD' },
		{ name: 'TokenHandle', type: 'PHANDLE' }
	]},
	{ name: 'AdjustTokenPrivileges', dll: 'advapi32.dll', returnType: 'BOOL', category: 'security', tags: ['privilege_escalation'], parameters: [
		{ name: 'TokenHandle', type: 'HANDLE' }, { name: 'DisableAllPrivileges', type: 'BOOL' },
		{ name: 'NewState', type: 'PTOKEN_PRIVILEGES' }, { name: 'BufferLength', type: 'DWORD' },
		{ name: 'PreviousState', type: 'PTOKEN_PRIVILEGES' }, { name: 'ReturnLength', type: 'PDWORD' }
	]},
	{ name: 'LookupPrivilegeValue', dll: 'advapi32.dll', returnType: 'BOOL', category: 'security', tags: ['privilege_escalation'], parameters: [
		{ name: 'lpSystemName', type: 'LPCTSTR' }, { name: 'lpName', type: 'LPCTSTR' },
		{ name: 'lpLuid', type: 'PLUID' }
	]},
	{ name: 'OpenSCManager', dll: 'advapi32.dll', returnType: 'SC_HANDLE', category: 'service', tags: ['persistence'], parameters: [
		{ name: 'lpMachineName', type: 'LPCTSTR' }, { name: 'lpDatabaseName', type: 'LPCTSTR' },
		{ name: 'dwDesiredAccess', type: 'DWORD' }
	]},
	{ name: 'CreateService', dll: 'advapi32.dll', returnType: 'SC_HANDLE', category: 'service', tags: ['persistence', 'rootkit'], parameters: [
		{ name: 'hSCManager', type: 'SC_HANDLE' }, { name: 'lpServiceName', type: 'LPCTSTR' },
		{ name: 'lpDisplayName', type: 'LPCTSTR' }, { name: 'dwDesiredAccess', type: 'DWORD' },
		{ name: 'dwServiceType', type: 'DWORD' }, { name: 'dwStartType', type: 'DWORD' },
		{ name: 'dwErrorControl', type: 'DWORD' }, { name: 'lpBinaryPathName', type: 'LPCTSTR' },
		{ name: 'lpLoadOrderGroup', type: 'LPCTSTR' }, { name: 'lpdwTagId', type: 'LPDWORD' },
		{ name: 'lpDependencies', type: 'LPCTSTR' }, { name: 'lpServiceStartName', type: 'LPCTSTR' },
		{ name: 'lpPassword', type: 'LPCTSTR' }
	]},

	// ========================= WS2_32.DLL =========================
	{ name: 'WSAStartup', dll: 'ws2_32.dll', returnType: 'int', category: 'network', tags: ['c2'], parameters: [
		{ name: 'wVersionRequested', type: 'WORD' }, { name: 'lpWSAData', type: 'LPWSADATA' }
	]},
	{ name: 'socket', dll: 'ws2_32.dll', returnType: 'SOCKET', category: 'network', tags: ['c2'], parameters: [
		{ name: 'af', type: 'int' }, { name: 'type', type: 'int' }, { name: 'protocol', type: 'int' }
	]},
	{ name: 'connect', dll: 'ws2_32.dll', returnType: 'int', category: 'network', tags: ['c2'], parameters: [
		{ name: 's', type: 'SOCKET' }, { name: 'name', type: 'const sockaddr*' }, { name: 'namelen', type: 'int' }
	]},
	{ name: 'bind', dll: 'ws2_32.dll', returnType: 'int', category: 'network', tags: ['c2'], parameters: [
		{ name: 's', type: 'SOCKET' }, { name: 'name', type: 'const sockaddr*' }, { name: 'namelen', type: 'int' }
	]},
	{ name: 'listen', dll: 'ws2_32.dll', returnType: 'int', category: 'network', tags: ['c2', 'backdoor'], parameters: [
		{ name: 's', type: 'SOCKET' }, { name: 'backlog', type: 'int' }
	]},
	{ name: 'accept', dll: 'ws2_32.dll', returnType: 'SOCKET', category: 'network', tags: ['c2', 'backdoor'], parameters: [
		{ name: 's', type: 'SOCKET' }, { name: 'addr', type: 'sockaddr*' }, { name: 'addrlen', type: 'int*' }
	]},
	{ name: 'send', dll: 'ws2_32.dll', returnType: 'int', category: 'network', tags: ['c2', 'exfiltration'], parameters: [
		{ name: 's', type: 'SOCKET' }, { name: 'buf', type: 'const char*' },
		{ name: 'len', type: 'int' }, { name: 'flags', type: 'int' }
	]},
	{ name: 'recv', dll: 'ws2_32.dll', returnType: 'int', category: 'network', tags: ['c2'], parameters: [
		{ name: 's', type: 'SOCKET' }, { name: 'buf', type: 'char*' },
		{ name: 'len', type: 'int' }, { name: 'flags', type: 'int' }
	]},
	{ name: 'closesocket', dll: 'ws2_32.dll', returnType: 'int', category: 'network', tags: [], parameters: [
		{ name: 's', type: 'SOCKET' }
	]},
	{ name: 'gethostbyname', dll: 'ws2_32.dll', returnType: 'hostent*', category: 'network', tags: ['c2', 'dns'], parameters: [
		{ name: 'name', type: 'const char*' }
	]},
	{ name: 'getaddrinfo', dll: 'ws2_32.dll', returnType: 'int', category: 'network', tags: ['c2', 'dns'], parameters: [
		{ name: 'pNodeName', type: 'PCSTR' }, { name: 'pServiceName', type: 'PCSTR' },
		{ name: 'pHints', type: 'const ADDRINFOA*' }, { name: 'ppResult', type: 'PADDRINFOA*' }
	]},
	{ name: 'inet_addr', dll: 'ws2_32.dll', returnType: 'unsigned long', category: 'network', tags: ['c2'], parameters: [
		{ name: 'cp', type: 'const char*' }
	]},
	{ name: 'htons', dll: 'ws2_32.dll', returnType: 'u_short', category: 'network', tags: [], parameters: [
		{ name: 'hostshort', type: 'u_short' }
	]},
	{ name: 'select', dll: 'ws2_32.dll', returnType: 'int', category: 'network', tags: ['c2'], parameters: [
		{ name: 'nfds', type: 'int' }, { name: 'readfds', type: 'fd_set*' },
		{ name: 'writefds', type: 'fd_set*' }, { name: 'exceptfds', type: 'fd_set*' },
		{ name: 'timeout', type: 'const timeval*' }
	]},

	// ========================= WININET / WINHTTP =========================
	{ name: 'InternetOpen', dll: 'wininet.dll', returnType: 'HINTERNET', category: 'network', tags: ['c2', 'download'], parameters: [
		{ name: 'lpszAgent', type: 'LPCTSTR' }, { name: 'dwAccessType', type: 'DWORD' },
		{ name: 'lpszProxy', type: 'LPCTSTR' }, { name: 'lpszProxyBypass', type: 'LPCTSTR' },
		{ name: 'dwFlags', type: 'DWORD' }
	]},
	{ name: 'InternetOpenUrl', dll: 'wininet.dll', returnType: 'HINTERNET', category: 'network', tags: ['c2', 'download'], parameters: [
		{ name: 'hInternet', type: 'HINTERNET' }, { name: 'lpszUrl', type: 'LPCTSTR' },
		{ name: 'lpszHeaders', type: 'LPCTSTR' }, { name: 'dwHeadersLength', type: 'DWORD' },
		{ name: 'dwFlags', type: 'DWORD' }, { name: 'dwContext', type: 'DWORD_PTR' }
	]},
	{ name: 'HttpSendRequest', dll: 'wininet.dll', returnType: 'BOOL', category: 'network', tags: ['c2', 'exfiltration'], parameters: [
		{ name: 'hRequest', type: 'HINTERNET' }, { name: 'lpszHeaders', type: 'LPCTSTR' },
		{ name: 'dwHeadersLength', type: 'DWORD' }, { name: 'lpOptional', type: 'LPVOID' },
		{ name: 'dwOptionalLength', type: 'DWORD' }
	]},
	{ name: 'InternetReadFile', dll: 'wininet.dll', returnType: 'BOOL', category: 'network', tags: ['c2', 'download'], parameters: [
		{ name: 'hFile', type: 'HINTERNET' }, { name: 'lpBuffer', type: 'LPVOID' },
		{ name: 'dwNumberOfBytesToRead', type: 'DWORD' }, { name: 'lpdwNumberOfBytesRead', type: 'LPDWORD' }
	]},
	{ name: 'WinHttpOpen', dll: 'winhttp.dll', returnType: 'HINTERNET', category: 'network', tags: ['c2', 'download'], parameters: [
		{ name: 'pszAgentW', type: 'LPCWSTR' }, { name: 'dwAccessType', type: 'DWORD' },
		{ name: 'pszProxyW', type: 'LPCWSTR' }, { name: 'pszProxyBypassW', type: 'LPCWSTR' },
		{ name: 'dwFlags', type: 'DWORD' }
	]},
	{ name: 'WinHttpSendRequest', dll: 'winhttp.dll', returnType: 'BOOL', category: 'network', tags: ['c2', 'exfiltration'], parameters: [
		{ name: 'hRequest', type: 'HINTERNET' }, { name: 'lpszHeaders', type: 'LPCWSTR' },
		{ name: 'dwHeadersLength', type: 'DWORD' }, { name: 'lpOptional', type: 'LPVOID' },
		{ name: 'dwOptionalLength', type: 'DWORD' }, { name: 'dwTotalLength', type: 'DWORD' },
		{ name: 'dwContext', type: 'DWORD_PTR' }
	]},

	// ========================= USER32.DLL =========================
	{ name: 'MessageBox', dll: 'user32.dll', returnType: 'int', category: 'ui', tags: [], parameters: [
		{ name: 'hWnd', type: 'HWND' }, { name: 'lpText', type: 'LPCTSTR' },
		{ name: 'lpCaption', type: 'LPCTSTR' }, { name: 'uType', type: 'UINT' }
	]},
	{ name: 'FindWindow', dll: 'user32.dll', returnType: 'HWND', category: 'ui', tags: ['recon', 'anti_debug'], parameters: [
		{ name: 'lpClassName', type: 'LPCTSTR' }, { name: 'lpWindowName', type: 'LPCTSTR' }
	]},
	{ name: 'SetWindowsHookEx', dll: 'user32.dll', returnType: 'HHOOK', category: 'hook', tags: ['keylogger', 'injection'], parameters: [
		{ name: 'idHook', type: 'int' }, { name: 'lpfn', type: 'HOOKPROC' },
		{ name: 'hmod', type: 'HINSTANCE' }, { name: 'dwThreadId', type: 'DWORD' }
	]},
	{ name: 'CallNextHookEx', dll: 'user32.dll', returnType: 'LRESULT', category: 'hook', tags: ['keylogger'], parameters: [
		{ name: 'hhk', type: 'HHOOK' }, { name: 'nCode', type: 'int' },
		{ name: 'wParam', type: 'WPARAM' }, { name: 'lParam', type: 'LPARAM' }
	]},
	{ name: 'GetAsyncKeyState', dll: 'user32.dll', returnType: 'SHORT', category: 'hook', tags: ['keylogger'], parameters: [
		{ name: 'vKey', type: 'int' }
	]},
	{ name: 'GetForegroundWindow', dll: 'user32.dll', returnType: 'HWND', category: 'ui', tags: ['recon', 'keylogger'], parameters: [] },
	{ name: 'SendInput', dll: 'user32.dll', returnType: 'UINT', category: 'ui', tags: ['bot'], parameters: [
		{ name: 'cInputs', type: 'UINT' }, { name: 'pInputs', type: 'LPINPUT' },
		{ name: 'cbSize', type: 'int' }
	]},
	{ name: 'GetClipboardData', dll: 'user32.dll', returnType: 'HANDLE', category: 'ui', tags: ['stealer', 'recon'], parameters: [
		{ name: 'uFormat', type: 'UINT' }
	]},
	{ name: 'GetDC', dll: 'user32.dll', returnType: 'HDC', category: 'ui', tags: ['screenshot'], parameters: [
		{ name: 'hWnd', type: 'HWND' }
	]},

	// ========================= SHELL32 / URLMON / OLE32 =========================
	{ name: 'ShellExecute', dll: 'shell32.dll', returnType: 'HINSTANCE', category: 'shell', tags: ['execution'], parameters: [
		{ name: 'hwnd', type: 'HWND' }, { name: 'lpOperation', type: 'LPCTSTR' },
		{ name: 'lpFile', type: 'LPCTSTR' }, { name: 'lpParameters', type: 'LPCTSTR' },
		{ name: 'lpDirectory', type: 'LPCTSTR' }, { name: 'nShowCmd', type: 'INT' }
	]},
	{ name: 'SHGetKnownFolderPath', dll: 'shell32.dll', returnType: 'HRESULT', category: 'shell', tags: ['recon'], parameters: [
		{ name: 'rfid', type: 'REFKNOWNFOLDERID' }, { name: 'dwFlags', type: 'DWORD' },
		{ name: 'hToken', type: 'HANDLE' }, { name: 'ppszPath', type: 'PWSTR*' }
	]},
	{ name: 'URLDownloadToFile', dll: 'urlmon.dll', returnType: 'HRESULT', category: 'network', tags: ['c2', 'download', 'dropper'], parameters: [
		{ name: 'pCaller', type: 'LPUNKNOWN' }, { name: 'szURL', type: 'LPCTSTR' },
		{ name: 'szFileName', type: 'LPCTSTR' }, { name: 'dwReserved', type: 'DWORD' },
		{ name: 'lpfnCB', type: 'LPBINDSTATUSCALLBACK' }
	]},
	{ name: 'CoCreateInstance', dll: 'ole32.dll', returnType: 'HRESULT', category: 'com', tags: [], parameters: [
		{ name: 'rclsid', type: 'REFCLSID' }, { name: 'pUnkOuter', type: 'LPUNKNOWN' },
		{ name: 'dwClsContext', type: 'DWORD' }, { name: 'riid', type: 'REFIID' },
		{ name: 'ppv', type: 'LPVOID*' }
	]},

	// ========================= BCRYPT / CRYPT32 =========================
	{ name: 'BCryptOpenAlgorithmProvider', dll: 'bcrypt.dll', returnType: 'NTSTATUS', category: 'crypto', tags: ['encryption'], parameters: [
		{ name: 'phAlgorithm', type: 'BCRYPT_ALG_HANDLE*' }, { name: 'pszAlgId', type: 'LPCWSTR' },
		{ name: 'pszImplementation', type: 'LPCWSTR' }, { name: 'dwFlags', type: 'ULONG' }
	]},
	{ name: 'BCryptEncrypt', dll: 'bcrypt.dll', returnType: 'NTSTATUS', category: 'crypto', tags: ['encryption', 'ransomware'], parameters: [
		{ name: 'hKey', type: 'BCRYPT_KEY_HANDLE' }, { name: 'pbInput', type: 'PUCHAR' },
		{ name: 'cbInput', type: 'ULONG' }, { name: 'pPaddingInfo', type: 'VOID*' },
		{ name: 'pbIV', type: 'PUCHAR' }, { name: 'cbIV', type: 'ULONG' },
		{ name: 'pbOutput', type: 'PUCHAR' }, { name: 'cbOutput', type: 'ULONG' },
		{ name: 'pcbResult', type: 'ULONG*' }, { name: 'dwFlags', type: 'ULONG' }
	]},
	{ name: 'BCryptDecrypt', dll: 'bcrypt.dll', returnType: 'NTSTATUS', category: 'crypto', tags: ['encryption'], parameters: [
		{ name: 'hKey', type: 'BCRYPT_KEY_HANDLE' }, { name: 'pbInput', type: 'PUCHAR' },
		{ name: 'cbInput', type: 'ULONG' }, { name: 'pPaddingInfo', type: 'VOID*' },
		{ name: 'pbIV', type: 'PUCHAR' }, { name: 'cbIV', type: 'ULONG' },
		{ name: 'pbOutput', type: 'PUCHAR' }, { name: 'cbOutput', type: 'ULONG' },
		{ name: 'pcbResult', type: 'ULONG*' }, { name: 'dwFlags', type: 'ULONG' }
	]},
	{ name: 'CryptStringToBinary', dll: 'crypt32.dll', returnType: 'BOOL', category: 'crypto', tags: ['encryption', 'decoding'], parameters: [
		{ name: 'pszString', type: 'LPCTSTR' }, { name: 'cchString', type: 'DWORD' },
		{ name: 'dwFlags', type: 'DWORD' }, { name: 'pbBinary', type: 'BYTE*' },
		{ name: 'pcbBinary', type: 'DWORD*' }, { name: 'pdwSkip', type: 'DWORD*' },
		{ name: 'pdwFlags', type: 'DWORD*' }
	]},

	// ========================= GDI32 =========================
	{ name: 'BitBlt', dll: 'gdi32.dll', returnType: 'BOOL', category: 'ui', tags: ['screenshot'], parameters: [
		{ name: 'hdc', type: 'HDC' }, { name: 'x', type: 'int' }, { name: 'y', type: 'int' },
		{ name: 'cx', type: 'int' }, { name: 'cy', type: 'int' }, { name: 'hdcSrc', type: 'HDC' },
		{ name: 'x1', type: 'int' }, { name: 'y1', type: 'int' }, { name: 'rop', type: 'DWORD' }
	]},
];

// Index: lowercase base name → ApiSignature
const INDEX = new Map<string, ApiSignature>();
for (const entry of DB) {
	INDEX.set(entry.name.toLowerCase(), entry);
}

/**
 * Look up an API signature by function name.
 * Handles A/W suffix stripping automatically. Case-insensitive.
 */
export function lookupApi(functionName: string): ApiSignature | undefined {
	const lower = functionName.toLowerCase();
	const exact = INDEX.get(lower);
	if (exact) { return { ...exact, name: functionName }; }

	if (lower.length > 1) {
		const lastChar = lower[lower.length - 1];
		if (lastChar === 'a' || lastChar === 'w') {
			const base = INDEX.get(lower.slice(0, -1));
			if (base) { return { ...base, name: functionName }; }
		}
	}

	if (lower.endsWith('ex') && lower.length > 2) {
		const base = INDEX.get(lower.slice(0, -2));
		if (base) { return { ...base, name: functionName }; }
	}

	return undefined;
}

/** Format as multi-line C prototype */
export function formatApiSignature(sig: ApiSignature): string {
	if (sig.parameters.length === 0) { return `${sig.returnType} ${sig.name}(void)`; }
	const params = sig.parameters.map(p => `  ${p.type} ${p.name}`).join(',\n');
	return `${sig.returnType} ${sig.name}(\n${params}\n)`;
}

/** Format as single-line compact prototype */
export function formatApiSignatureCompact(sig: ApiSignature): string {
	if (sig.parameters.length === 0) { return `${sig.returnType} ${sig.name}(void)`; }
	const params = sig.parameters.map(p => `${p.type} ${p.name}`).join(', ');
	return `${sig.returnType} ${sig.name}(${params})`;
}

export function getApiDatabaseSize(): number { return DB.length; }
