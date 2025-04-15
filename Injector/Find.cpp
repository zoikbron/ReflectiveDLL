#include "process.h"


int FindTarget(char * Process){

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);
    int pid;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    if(!Process32First(hSnap,&pe32)) return 0;

    while(Process32Next(hSnap,&pe32)){

        if(lstrcmpiA(pe32.szExeFile,Process)==0){
            pid = pe32.th32ProcessID;
            break;

        }

    }
    return pid;
    


}

