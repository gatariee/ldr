#include "windows.h"
#include <stdio.h>

constexpr unsigned int SEED = 0xdeadbeef;

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

VOID JessRecursive( const char * known, size_t len, char * message, int depth, int currentDepth, unsigned int targetHash ) {
    if ( currentDepth == depth ) {
        message[len + currentDepth] = '\0';
        if ( crc32h( message ) == targetHash ) {
            printf( "Match found: %s\n", message );
            exit( 0 );
        }
        return;
    }

    for ( char c = 33; c <= 126; ++c ) {
        message[len + currentDepth] = c;
        JessRecursive( known, len, message, depth, currentDepth + 1, targetHash );
    }
}

VOID Jess( const char * known, size_t len, int depth, unsigned int targetHash ) {
    char message[64];
    memcpy( message, known, len );
    JessRecursive( known, len, message, depth, 0, targetHash );
}

INT main( INT argc, CHAR * argv[] ) {
    const unsigned int targetHash = 4081440294;
    const char         known[]    = { 0x41, 0x53, 0x48, 0x73, 0x75, 0x64 };
    Jess( known, sizeof( known ), 4, targetHash );

    return TRUE;
}
