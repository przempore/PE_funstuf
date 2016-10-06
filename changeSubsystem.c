#include <stdio.h>
#include <windows.h>

int main(int argc, char** argv)
{
  HANDLE hMapObject, hFile;
  LPVOID lpBase;
  IMAGE_OPTIONAL_HEADER opHeader;
  PIMAGE_DOS_HEADER dosHeader;
  PIMAGE_NT_HEADERS ntHeader;

  hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {printf("\nERROR: Could not open file specified.\n"); return 1;}
  
  hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);
  dosHeader = (PIMAGE_DOS_HEADER)lpBase;
  
  ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader) + (dosHeader->e_lfanew));
  if (ntHeader->Signature == IMAGE_NT_SIGNATURE)
  {
    opHeader = ntHeader->OptionalHeader;
    int subsystem = -1;
    printf("\nSubSystem type: %d\n", opHeader.Subsystem);
    printf("Enter new subsystem type: ");
    scanf("%d", &subsystem);
    opHeader.Subsystem = subsystem;
    printf("\nSubSystem type: %d\n", opHeader.Subsystem);
  }

  UnmapViewOfFile(lpBase);
  CloseHandle(hMapObject);

  return 0;
}
