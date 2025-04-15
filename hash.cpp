#include ".\DLL\help.h"

DWORD modulehash(LPCWSTR modulename){

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
        ULONG_PTR uiValueB = (ULONG_PTR)pEntry->BaseDllName.Buffer;
        ULONG_PTR usCounter = pEntry->BaseDllName.Length;
        ULONG_PTR uiValueC = 0;
        if(lstrcmpiW(pEntry->BaseDllName.Buffer,L"ntdll.dll")==0){
            printf("%ws",pEntry->BaseDllName.Buffer);
         do
		{
			uiValueC = ror( (DWORD)uiValueC );
			// normalize to uppercase if the madule name is in lowercase
			if( *((BYTE *)uiValueB) >= 'a' )
				uiValueC += *((BYTE *)uiValueB) - 0x20;
			else
				uiValueC += *((BYTE *)uiValueB);
			uiValueB++;
		} while( --usCounter ); 
		return (DWORD)uiValueC;

        }
        return NULL;
}
}


void main (int argc,char * argv[]){
    if(argc > 2 || argc <= 1) {printf ("One argument at least, Program.exe Name");
     exit(1);}
    DWORD dwHash= hash(argv[1]);

    printf("0x%X",dwHash);



    }



    
