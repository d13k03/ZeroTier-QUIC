#include "Phy.hpp"

namespace ZeroTier {

QUIC_API_TABLE* MsQuic = NULL;

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
HQUIC QUICRegistration = NULL;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
HQUIC QUICConfigurationClient = NULL;
HQUIC QUICConfigurationServer = NULL;

unsigned int g_sock_id = 1;

void
EncodeHexBuffer(
    _In_reads_(BufferLen) uint8_t* Buffer,
    _In_ uint8_t BufferLen,
    _Out_writes_bytes_(2*BufferLen) char* HexString
    )
{
    #define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
    for (uint8_t i = 0; i < BufferLen; i++) {
        HexString[i*2]     = HEX_TO_CHAR(Buffer[i] >> 4);
        HexString[i*2 + 1] = HEX_TO_CHAR(Buffer[i] & 0xf);
    }
}

char *sslKeyLogFile = NULL;
uint32_t QUICSendBufferSize = 8192;

}
