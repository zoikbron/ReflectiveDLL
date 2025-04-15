#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#pragma intrinsic( _ReturnAddress )
#pragma comment (lib,"user32.lib")
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)_ReturnAddress(); }
typedef BOOL (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );
NTSTATUS (NTAPI * pNtFlushInstructionCache)(HANDLE ProcessHandle,PVOID BaseAddress,ULONG NumberOfBytesToFlush);


 __declspec(dllexport) void Reflecting();

void Reflecting(){

     ULONG_PTR pLibraryAddress = caller();
    ULONG_PTR Verify;

    while(TRUE){

        if(((IMAGE_DOS_HEADER *)pLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE){
                Verify = (ULONG_PTR)((IMAGE_DOS_HEADER *)pLibraryAddress)->e_lfanew;
                
                if(Verify >= sizeof(IMAGE_DOS_HEADER) && Verify < 1024){
                Verify += pLibraryAddress;
                if(((IMAGE_NT_HEADERS *)Verify)->Signature == IMAGE_NT_SIGNATURE){
					break;
                    
                }
                }
            
        }
        pLibraryAddress--;
    }
	char * BaseAddress = (char *)pLibraryAddress;
    IMAGE_DOS_HEADER * pDosHeader= (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS * pNtHeaders = (IMAGE_NT_HEADERS *)((BYTE *)pDosHeader + pDosHeader->e_lfanew);
    IMAGE_FILE_HEADER * pFileHeader = (IMAGE_FILE_HEADER *)&pNtHeaders->FileHeader;
    IMAGE_OPTIONAL_HEADER * pOptionalHeader = (IMAGE_OPTIONAL_HEADER *)&pNtHeaders->OptionalHeader;
	MessageBoxA( NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK );
	//pNtFlushInstructionCache = (NTSTATUS (NTAPI *)(HANDLE ,PVOID ,ULONG ))GetProcAddress(GetModuleHandleA("NTDLL.DLL"),"NtFlushInstructionCache");
	//pNtFlushInstructionCache( (HANDLE)-1, NULL, 0 );
	DLLMAIN EntryPoint = (DLLMAIN)((BYTE *)BaseAddress + pOptionalHeader->AddressOfEntryPoint);
    EntryPoint((HINSTANCE)BaseAddress, DLL_PROCESS_ATTACH, NULL);

}