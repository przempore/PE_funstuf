#include <iostream>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

using namespace std;

int main()
{
    HANDLE hFile, hFileMap;
    LPBYTE hMap;
    DWORD fileSize;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    PIMAGE_SECTION_HEADER sectionHeader;
    LPSTR filename = "c:\\blah";
    hFile = CreateFileA(filename, GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE){
        cout << "Couldn't create file" << endl;
        cin.get();
        return 0;
    }
    fileSize = GetFileSize(hFile, 0);
    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, fileSize, NULL);
    if (!hFileMap){
        cout << "Couldn't map file" << endl;
        CloseHandle(hFile);
        cin.get();
        return 0;
    }
    hMap = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, fileSize);
    if (!hMap){
        cout << "Couldn't map view of file" << endl;
        CloseHandle(hFile);
        CloseHandle(hFileMap);
        cin.get();
        return 0;
    }
    dosHeader = (PIMAGE_DOS_HEADER)hMap;
    ntHeader = (PIMAGE_NT_HEADERS)((DWORD)hMap + dosHeader->e_lfanew);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE && ntHeader->Signature != IMAGE_NT_SIGNATURE){
        cout << "Not a valid PE file" << endl;
        CloseHandle(hFile);
        CloseHandle(hFileMap);
        FlushViewOfFile(hMap, 0);
        UnmapViewOfFile(hMap);
        SetFilePointer(hFile, fileSize, NULL, FILE_BEGIN);
        SetEndOfFile(hFile);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        cin.get();
        return 0;
    }else{
        cout << "Valid PE" << endl;
    }
    cout << hex << ntHeader->FileHeader.NumberOfSections << " Sections" << endl<<endl;
    sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)hMap + dosHeader->e_lfanew + sizeof(IMAGE_NT_SIGNATURE)+sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_OPTIONAL_HEADER));
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections;i++){
        cout << "Name: " << sectionHeader[i].Name << endl;
        cout << "Virtual Address: " << hex << sectionHeader[i].VirtualAddress << endl;
        cout << "Virtual Size: " << hex << sectionHeader[i].Misc.VirtualSize << endl;
        cout << "Pointer To Raw Data: " << hex << sectionHeader[i].PointerToRawData << endl;
        cout << "Raw Size: " << hex << sectionHeader[i].SizeOfRawData << endl;
        cout << "Characteristics: " << hex << sectionHeader[i].Characteristics << endl << endl;
    }

    DWORD importDirectoryVA = ntHeader->OptionalHeader.DataDirectory[1].VirtualAddress; 
    DWORD iatOffsetInSection;
    //sets section which contains iat
    int section = -1;

    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++){
        if (sectionHeader[i].VirtualAddress <= importDirectoryVA &&
        (sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize)>importDirectoryVA){
            iatOffsetInSection = importDirectoryVA - sectionHeader[i].VirtualAddress;
            iatOffsetInSection += sectionHeader[i].PointerToRawData;
            section = i;
        }
    }

    cout << "IAT was found at offset " << hex<< iatOffsetInSection << " in section " << sectionHeader[section].Name << endl;
    if (section == -1){
        cout << "IAT not found in sections" << endl;
    }else{
        cout << "IAT found" << endl;
        PIMAGE_IMPORT_DESCRIPTOR firstDll = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)ntHeader->OptionalHeader.ImageBase + sectionHeader[section].VirtualAddress + iatOffsetInSection);
        cout << (DWORD)firstDll << endl;
        int i = 0;
        cout << firstDll[0].Name << endl;
        while(firstDll[i].Name != 0){
            cout << firstDll[i].Name << ":" << endl;
            i++;
        }
    }
    CloseHandle(hFile);
    CloseHandle(hFileMap);
    FlushViewOfFile(hMap, 0);
    UnmapViewOfFile(hMap);
    SetFilePointer(hFile, fileSize, NULL, FILE_BEGIN);
    SetEndOfFile(hFile);
    CloseHandle(hFileMap);
    CloseHandle(hFile);
    cin.get();
    return 0;
}
