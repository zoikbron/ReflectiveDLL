#include "process.h"
#include <psapi.h>


typedef struct 
{
WORD  offset:12;
WORD type:4;
}IMAGE_RELOC,*PIMAGE_RELOC;
typedef struct {

    FILE * hFile;
    long filesize;

} FILE_ATTR,*PFILE_ATTR;

 

FILE_ATTR FileSize(char * dllpath){
    FILE_ATTR file;
    file.hFile = fopen(dllpath,"rb");
    fseek(file.hFile,0,SEEK_END);
    file.filesize = ftell(file.hFile);
    rewind(file.hFile);

    return file;



}

DWORD RVAtoOffset(DWORD RVA,IMAGE_SECTION_HEADER * pSection,IMAGE_FILE_HEADER * pFile){
    DWORD FileOffset;
    for(int i = 0; i < pFile->NumberOfSections; i++){
        DWORD SectionStart = pSection[i].VirtualAddress;
        DWORD SectionEnd = SectionStart + pSection[i].Misc.VirtualSize;
        if(RVA >= SectionStart && RVA < SectionEnd){

            FileOffset = RVA - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
            return FileOffset;
        }

    }

}
HMODULE GetRemoteDllBase(HANDLE hProcess, const char *dllName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (K32GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                if (lstrcmpiA(szModName, dllName) == 0) {
                    return hMods[i]; // Return base address
                }
            }
        }
    }
    return NULL; // Not found
}


HMODULE RemoteLoadLibrary(HANDLE hProc, char * Library){
    void * pLoadLibrary;
    DWORD oldProtect;
    LPVOID Memory;
    DWORD remoteDllBase;
    HANDLE th;
    Memory = VirtualAllocEx(hProc,0,strlen(Library),MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE);
    WriteProcessMemory(hProc,Memory,Library,strlen(Library),NULL);
    pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"),"LoadLibraryA");
    VirtualProtectEx(hProc,Memory,strlen(Library),PAGE_EXECUTE_READ,&oldProtect);
    th = CreateRemoteThread(hProc,0,0,(LPTHREAD_START_ROUTINE)pLoadLibrary,Memory,0,0);
    if(th !=NULL){
        WaitForSingleObject(th,500);
        CloseHandle(th);
    }
  
    HMODULE hLibrary = GetRemoteDllBase(hProc,Library);
    return hLibrary;


}

ULONGLONG RemoteExported(HANDLE hProc,HMODULE library,char * function){
        
        unsigned char info[0x4000];
        ReadProcessMemory(hProc,library,info,0x4000,NULL);
        IMAGE_DOS_HEADER * LibraryDosHeader = (IMAGE_DOS_HEADER *)info;
        

        IMAGE_NT_HEADERS * LibraryNTHeader = (IMAGE_NT_HEADERS *)((BYTE *)LibraryDosHeader + LibraryDosHeader->e_lfanew);
            
        IMAGE_OPTIONAL_HEADER * pOptional = (IMAGE_OPTIONAL_HEADER *)&LibraryNTHeader->OptionalHeader;
        unsigned char * Image =(unsigned char *)malloc(pOptional->SizeOfImage);
        ReadProcessMemory(hProc,library,Image,(SIZE_T)pOptional->SizeOfImage,NULL);
        LibraryDosHeader = (IMAGE_DOS_HEADER *)Image;
        LibraryNTHeader =  (IMAGE_NT_HEADERS *)((BYTE *)LibraryDosHeader + LibraryDosHeader->e_lfanew);
        IMAGE_FILE_HEADER  * pFileHeader = (IMAGE_FILE_HEADER *)&LibraryNTHeader->FileHeader;
        IMAGE_SECTION_HEADER * pSection = (IMAGE_SECTION_HEADER *)((BYTE *)&LibraryNTHeader->OptionalHeader + LibraryNTHeader->FileHeader.SizeOfOptionalHeader);
        IMAGE_DATA_DIRECTORY * pDataDirectory = (IMAGE_DATA_DIRECTORY *)&pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        IMAGE_EXPORT_DIRECTORY * pExport = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)LibraryDosHeader + pDataDirectory->VirtualAddress);

        DWORD * pAddressOfFunctions = (DWORD *)((BYTE *)Image + pExport->AddressOfFunctions);
        DWORD * pAddressOfNames = (DWORD *)((BYTE *)Image + pExport->AddressOfNames);
        WORD * pAddressOfNameOrdinals = (WORD *)((BYTE *)Image + pExport->AddressOfNameOrdinals);
        for(int i = 0;i < pExport->NumberOfNames;i++){
                char * sTemp = (char *)((BYTE *)Image + pAddressOfNames[i]);
                if(lstrcmpiA(function,sTemp)==0){
                    void * Address = ((BYTE *)library + (DWORD_PTR)pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
                    
                    printf("MODULE: %s, Address: %p\n",sTemp,pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
                    return (ULONGLONG)Address;
                }


        }








}




void ManualMapping(HANDLE hProc,unsigned char * basedll){
    LPVOID Memory;
    IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER *)basedll;
    IMAGE_NT_HEADERS * pNtHeaders = (IMAGE_NT_HEADERS *)((BYTE *)pDosHeader + pDosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptional = (IMAGE_OPTIONAL_HEADER *)&pNtHeaders->OptionalHeader;
    IMAGE_FILE_HEADER * pFileHeaders  = (IMAGE_FILE_HEADER *)&pNtHeaders->FileHeader;
    IMAGE_SECTION_HEADER * pSection = (IMAGE_SECTION_HEADER*)((BYTE *)pOptional + pFileHeaders->SizeOfOptionalHeader);
    IMAGE_DATA_DIRECTORY * pDataDirectory = (IMAGE_DATA_DIRECTORY *)&pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    DWORD IMPORTRVA = RVAtoOffset(pDataDirectory->VirtualAddress,pSection,pFileHeaders);
    IMAGE_IMPORT_DESCRIPTOR * pImport = (IMAGE_IMPORT_DESCRIPTOR *)(basedll + IMPORTRVA);
    


    Memory = VirtualAllocEx(hProc,0,pOptional->SizeOfImage,MEM_RESERVE | MEM_COMMIT,PAGE_EXECUTE_READWRITE);

    //for(int i = 0; i < pOptional->SizeOfHeaders;i++){
    WriteProcessMemory(hProc,Memory,basedll,(size_t)pOptional->SizeOfHeaders,NULL);
    //}
    
    for(int i = 0; i < pFileHeaders->NumberOfSections; i++){
        BYTE * pSector = (BYTE *)((BYTE *)Memory + pSection[i].VirtualAddress);
        BYTE * pData = (BYTE *)(basedll + pSection[i].PointerToRawData);

        //for(int n = 0;n < pSection[i].SizeOfRawData;n++){
            //WriteProcessMemory(hProc,&((BYTE *)pSector)[n],&((BYTE *)pData)[n],1,NULL);
        WriteProcessMemory(hProc,pSector,pData,(size_t)pSection[i].SizeOfRawData,NULL);
        //}


    }
    HMODULE library;
    if(pDataDirectory->Size){
        
        
       for(int i = 0; pImport[i].Name != 0;i++){
        DWORD NAMERVA = RVAtoOffset(pImport[i].Name,pSection,pFileHeaders);
        char * NAME = (char *)(basedll + NAMERVA);
        library = RemoteLoadLibrary(hProc,NAME);
       

        DWORD INTRVA = RVAtoOffset(pImport[i].OriginalFirstThunk,pSection,pFileHeaders);
        DWORD IATRVA = pImport[i].FirstThunk;
        IMAGE_THUNK_DATA * pINT = (IMAGE_THUNK_DATA *)(basedll + INTRVA);
        IMAGE_THUNK_DATA *pIAT = (IMAGE_THUNK_DATA *)((BYTE *)Memory + IATRVA);
        for(int n = 0; pINT[n].u1.AddressOfData !=0;n++){
        DWORD BYNAMERVA = RVAtoOffset(pINT[n].u1.AddressOfData,pSection,pFileHeaders);
        IMAGE_IMPORT_BY_NAME * pByName = (IMAGE_IMPORT_BY_NAME *)(basedll + BYNAMERVA);
        ULONGLONG FuctionAddress = RemoteExported(hProc,library,pByName->Name);
        WriteProcessMemory(hProc,&pIAT[n].u1.Function,&FuctionAddress,sizeof(FuctionAddress),NULL);
        }

       }


    }
    if(pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size){
        BYTE * delta = (BYTE *)((BYTE*)Memory - pOptional->ImageBase); 
        pDataDirectory = (IMAGE_DATA_DIRECTORY *)&pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        DWORD BASERELOCRVA = RVAtoOffset(pDataDirectory->VirtualAddress,pSection,pFileHeaders);
        IMAGE_BASE_RELOCATION * pBaseReloc = (IMAGE_BASE_RELOCATION *)((BYTE *)basedll + BASERELOCRVA );
        
        while(pBaseReloc->SizeOfBlock){
            void * RelocAddress = ((BYTE *)Memory + pBaseReloc->VirtualAddress);
            int Counter = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            IMAGE_RELOC * pReloc = (IMAGE_RELOC *)(pBaseReloc + 1);

            for(int n = 0;pReloc[n].offset !=0;n++){
                BYTE * AddressToPatch = (BYTE *)((BYTE *)RelocAddress + pReloc[n].offset);
                if(pReloc[n].type == IMAGE_REL_BASED_DIR64) {
                    ULONG_PTR originalvalue;
                    ReadProcessMemory(hProc,AddressToPatch,&originalvalue,sizeof(ULONG_PTR),NULL);
                    ULONG_PTR newValue = originalvalue + (ULONG_PTR)delta;
                    WriteProcessMemory(hProc,AddressToPatch,(LPCVOID)newValue,sizeof(ULONG_PTR),NULL);
            }
            if(pReloc[n].type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD originalvalue;
                ReadProcessMemory(hProc,AddressToPatch,&originalvalue,sizeof(DWORD),NULL);
                DWORD newValue = originalvalue + (DWORD)delta;
                WriteProcessMemory(hProc,AddressToPatch,(LPCVOID)newValue,sizeof(DWORD),NULL);
                printf("HIGHLOW");
            }
                if(pReloc[n].type == IMAGE_REL_BASED_HIGH ) {
                WORD originalvalue;
                ReadProcessMemory(hProc,AddressToPatch,&originalvalue,sizeof(HIWORD(originalvalue)),NULL);
                WORD newValue = originalvalue + HIWORD((WORD)delta);
                WriteProcessMemory(hProc,AddressToPatch,(LPCVOID)newValue,sizeof(HIWORD(newValue)),NULL);
                printf("high");
                }
			    
           }
        
            
        pBaseReloc = (IMAGE_BASE_RELOCATION *)((BYTE *)pBaseReloc + pBaseReloc->SizeOfBlock);
        }
    
    }
    pDataDirectory = (IMAGE_DATA_DIRECTORY *)&pOptional->DataDirectory[0];
    DWORD FileOffset = RVAtoOffset(pDataDirectory->VirtualAddress,pSection,pFileHeaders);
    IMAGE_EXPORT_DIRECTORY * pExportDirectory = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)basedll + FileOffset);
    DWORD AddressOfNameOffset = RVAtoOffset(pExportDirectory->AddressOfNames,pSection,pFileHeaders);
    DWORD AddressOfFunctionsOffset = RVAtoOffset(pExportDirectory->AddressOfFunctions,pSection,pFileHeaders);
    DWORD AddressOfNameOrdinalsOffset = RVAtoOffset(pExportDirectory->AddressOfNameOrdinals,pSection,pFileHeaders);
    
    DWORD * pName = (DWORD *)((BYTE *)basedll+ AddressOfNameOffset);
    DWORD * pFunctions = (DWORD * )((BYTE *)basedll+ AddressOfFunctionsOffset);
    WORD * pOrdinals = (WORD *)((BYTE *)basedll + AddressOfNameOrdinalsOffset);


    void * Reflecting;
   
    for (int n = 0; n < pExportDirectory->NumberOfNames; n++)
    {
        DWORD NamesRVA = RVAtoOffset(pName[n],pSection,pFileHeaders);
        char * sTemp = (char *) ((BYTE *)basedll + NamesRVA);
        printf(sTemp);
        if(strcmp(sTemp,"?Reflecting@@YAXXZ")==0){

        Reflecting = (void *)((BYTE *)Memory + pFunctions[pOrdinals[n]]);
        printf("%p",(void *)Reflecting);
        break;
        }
    }
    getchar();
    HANDLE th;
    th = CreateRemoteThread(hProc,0,0,(LPTHREAD_START_ROUTINE)Reflecting,0,0,0);
    if(th !=NULL){
        WaitForSingleObject(th,500);
        CloseHandle(th);

    }


printf("lail");

}

int main() {
    unsigned char * buffer;
    HANDLE hProc;
    FILE_ATTR file;
    HANDLE th;
    int pid;


    
    file = FileSize("Z:\\RTO\\Intermediate\\Reflective DLL\\Injector\\basedll.dll");

    printf("File size: %d bytes\n", file.filesize);

    buffer = (unsigned char *)malloc(file.filesize);
    
    fread(buffer, 1, file.filesize, file.hFile);
    pid = FindTarget("lol.exe");
    printf("Process ID: %d\n", pid); 
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); 
    ManualMapping(hProc,buffer);
    
}

