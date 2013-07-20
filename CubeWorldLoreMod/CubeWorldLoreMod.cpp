#include <iostream>
#include <Windows.h>
#include <io.h>
#include <sstream>
#include <fcntl.h>
#include <time.h>
#include <TlHelp32.h>
#include <map>
#include <vector>
#include <regex>

#include "../libs/pugixml.hpp"

/*


#include <set>
#include <map>

#include <algorithm>
*/

using namespace std;
typedef unsigned __int64 QWORD;

void CreateDebugConsole()
{
	HANDLE lStdHandle = 0;
	int hConHandle = 0;
	FILE *fp = 0;
	AllocConsole();
	lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
	SetConsoleTitle(L"Fast Travel Mod");
	SetConsoleTextAttribute(lStdHandle, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	system("cls");
	fp = _fdopen(hConHandle, "w");
	*stdout = *fp;
	setvbuf(stdout, NULL, _IONBF, 0);
}

DWORD GetModuleSize(LPSTR strModuleName)
{
	MODULEENTRY32	lpme = { 0 };
	DWORD			dwSize = 0;
	DWORD			PID = GetCurrentProcessId();
	BOOL			isMod = 0;
	char			chModName[256];

	strcpy_s(chModName, strModuleName);
	_strlwr_s(chModName);

	HANDLE hSnapshotModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hSnapshotModule)
	{
		lpme.dwSize = sizeof(lpme);
		isMod = Module32First(hSnapshotModule, &lpme);
		while (isMod)
		{
			char *str = new char[4046];
			wcstombs(str, lpme.szExePath, sizeof(lpme.szExePath));
			if (strcmp(_strlwr(str), chModName))
			{
				dwSize = (DWORD) lpme.modBaseSize;
				CloseHandle(hSnapshotModule);
				return dwSize;
			}
			isMod = Module32Next(hSnapshotModule, &lpme);
		}
	}
	CloseHandle(hSnapshotModule);

	return 0;
}


DWORD FindPattern(DWORD start_offset, DWORD size, BYTE* pattern, char mask [])
{

	DWORD pos = 0;
	int searchLen = strlen(mask) - 1;
	for (DWORD retAddress = start_offset; retAddress < start_offset + size; retAddress++)
	{
		if (*(BYTE*) retAddress == pattern[pos] || mask[pos] == '?'){
			if (mask[pos + 1] == '\0')
				return (retAddress - searchLen);
			pos++;
		}
		else
			pos = 0;
	}
	return NULL;
}


void MakeJMP(BYTE *pAddress, DWORD dwJumpTo, DWORD dwLen)
{
	DWORD dwOldProtect, dwBkup, dwRelAddr;
	VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	dwRelAddr = (DWORD) (dwJumpTo - (DWORD) pAddress) - 5;
	*pAddress = 0xE9;
	*((DWORD *) (pAddress + 0x1)) = dwRelAddr;
	for (DWORD x = 0x5; x < dwLen; x++) *(pAddress + x) = 0x90;
	VirtualProtect(pAddress, dwLen, dwOldProtect, &dwBkup);

	return;

}

void fail(wchar_t* opcodes)
{
	wchar_t string[256];
	wsprintf(string, L"Failed to find %s opcodes\n", opcodes);
	wprintf(string);
	fflush(stdout);
	MessageBox(
		NULL,
		string,
		L"Opcode hot-replace failed",
		MB_ICONEXCLAMATION | MB_OK
		);
	exit(-1);
}

DWORD examine_prompt_internal = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x8B\x0A\x49\x83\xF9\x4C"),
	"xxxxxx");

DWORD examine_prompt_JMP_back = examine_prompt_internal + 5;

DWORD push_examine = examine_prompt_internal + 0x3BD;

DWORD push_nothing_special = FindPattern(reinterpret_cast<DWORD>(GetModuleHandle(NULL)), GetModuleSize("Cube.exe"),
	reinterpret_cast<PBYTE>("\x89\x45\xE4\x8D\x45\xD4\x50\x83\xEC\x18\x8B\xCC"),
	"xxxxxxxxxxxx");

DWORD push_nothing_special_JMP_back = push_nothing_special + 5 + 0x0A;

DWORD oldeax;
DWORD oldecx;
DWORD oldedx;
DWORD oldebx;
DWORD oldesp;
DWORD oldebp;
DWORD oldesi;
DWORD oldedi;



QWORD last_item_hash;
DWORD p_item_base;

byte last_id;
wchar_t* dialogue;
int seq = 0;
map < int, vector<wchar_t*>> lore_map;
bool dev_mode = false;


regex whitespace_strip("( +)|(\t+)");
void load_xml(){
	lore_map.clear();
	pugi::xml_document doc;
	pugi::xml_parse_result result = doc.load_file("./lore.xml");

	if (!result){
		printf("lore.xml could not be loaded\n");
	}

	pugi::xml_node lore = doc.child("descriptions");
	dev_mode = lore.attribute("dev_mode").as_bool();
	printf("Dev mode: %s\n", dev_mode ? "true" : "false");

	int count = 0;
	for (pugi::xml_node item = lore.child("item"); item; item = item.next_sibling("item"))
	{
		int id = item.attribute("id").as_int();
		for (pugi::xml_node text_node = item.child("text"); text_node; text_node = text_node.next_sibling("text"))
		{
			const char* text = text_node.text().get();
			string stripped = regex_replace(text, whitespace_strip, " ");
			printf("'%s' -> '%s'\n", text, stripped);

			size_t t;
			wchar_t* w_text = new wchar_t[1024];
			mbstowcs_s(&t, w_text, 1024, stripped.c_str(), 1024);
						
			lore_map[id].push_back(w_text);
			count++;
		}

	}
	printf("Loaded %d strings from XML\n", count);
}


void on_examine_prompt(){

	QWORD item_x = *((QWORD*) p_item_base + 0x1);
	QWORD item_z = *((QWORD*) p_item_base + 0x2);
	QWORD item_y = *((QWORD*) p_item_base + 0x3);

	QWORD item_hash = item_x ^ item_z ^ item_y;
	if (item_hash != last_item_hash)
	{
		seq = 0;
		last_item_hash = item_hash;
		last_id = *((byte*) p_item_base);
	}
	fflush(stdout);
	__asm
	{
			mov eax, [oldeax]
			mov ecx, [oldecx]
			mov edx, [oldedx]
			mov ebx, [oldebx]
			mov esp, [oldesp]
			mov ebp, [oldebp]
			mov esi, [oldesi]
			mov edi, [oldedi]

			MOV     ECX, DWORD PTR DS : [EDX]
			DEC     ECX
			CMP     ECX, 0x4C

			jmp[examine_prompt_JMP_back]
	}
}

__declspec(naked) void examine_prompt_asm(){
	__asm
	{
			mov[oldeax], eax
			mov[oldecx], ecx
			mov[oldedx], edx
			mov[oldebx], ebx
			mov[oldesp], esp
			mov[oldebp], ebp
			mov[oldesi], esi
			mov[oldedi], edi

			mov[p_item_base], edx

			jmp on_examine_prompt
	}
}

void on_push_nothing_special(){
	load_xml();

	printf("Item: %d\n", last_id);
	if (dialogue){
		delete dialogue;
		dialogue = NULL;
	}
	dialogue = new wchar_t[1024];
	if (lore_map.find(last_id) != lore_map.end()){
		
		srand(last_item_hash);
		int index = rand() % lore_map[last_id].size();
		wcscpy(dialogue, lore_map[last_id][index]);
	}
	else if (dev_mode) {
		swprintf(dialogue, L"This has id %d", last_id);
	}
	else {
		wcscpy(dialogue, L"There is nothing special");
	}

	__asm
	{
			mov eax, [oldeax]
			mov ecx, [oldecx]
			mov edx, [oldedx]
			mov ebx, [oldebx]
			mov esp, [oldesp]
			mov ebp, [oldebp]
			mov esi, [oldesi]
			mov edi, [oldedi]

			MOV     ECX, ESP
			PUSH[dialogue]

			jmp[push_nothing_special_JMP_back]
	}
}

__declspec(naked) void push_nothing_special_asm()
{
	__asm
	{
			mov[oldeax], eax
			mov[oldecx], ecx
			mov[oldedx], edx
			mov[oldebx], ebx
			mov[oldesp], esp
			mov[oldebp], ebp
			mov[oldesi], esi
			mov[oldedi], edi

			jmp on_push_nothing_special
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{

		//CreateDebugConsole();

		if (push_nothing_special){
			push_nothing_special += 0x0A;
			printf("Found PUSH nothing special : %x \n", push_nothing_special);

			MakeJMP((BYTE*) (push_nothing_special), (DWORD) push_nothing_special_asm, 0x7);

		}
		else {
			fail(L"push_nothing_special");
		}

		if (examine_prompt_internal)
		{
			printf("Found examine prompt opcodes: %x\n", examine_prompt_internal);
			MakeJMP((BYTE*) (examine_prompt_internal), (DWORD) examine_prompt_asm, 0x6);
			printf("\t and found push examine opcodes: %x\n", push_examine);
		}
		else {
			fail(L"examine_prompt_internal");
		}


		load_xml();


		fflush(stdout);

	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{
		printf("Exiting... closing stdout\n");
		fclose(stdout);
		exit(0);
	}

	return TRUE;
}
