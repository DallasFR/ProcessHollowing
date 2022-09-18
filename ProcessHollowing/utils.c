#include <Windows.h>


#include "utils.h"


BOOL _GetDataFromLocalFile(PPayload_Information _PayloadInfo, LPWSTR _FileToRun) {

    HANDLE _MyFile = CreateFile(_FileToRun, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD _FileSize = GetFileSize(_MyFile, NULL);
    LPVOID _PtrFileToRun = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)_FileSize);
    BOOL _FileReaded = ReadFile(_MyFile, _PtrFileToRun, _FileSize, NULL, NULL);

    _PayloadInfo->Addr = _PtrFileToRun;
    _PayloadInfo->Size = _FileSize;

    return _FileReaded;
}