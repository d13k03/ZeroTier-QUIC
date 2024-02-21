/*
 * Copyright (c)2013-2020 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2025-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

#ifndef ZT_PHY_HPP
#define ZT_PHY_HPP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <list>
#include <queue>
#include <stdexcept>

#if defined(_WIN32) || defined(_WIN64)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define ZT_PHY_SOCKFD_TYPE SOCKET
#define ZT_PHY_SOCKFD_NULL (INVALID_SOCKET)
#define ZT_PHY_SOCKFD_VALID(s) ((s) != INVALID_SOCKET)
#define ZT_PHY_CLOSE_SOCKET(s) ::closesocket(s)
#define ZT_PHY_MAX_SOCKETS (FD_SETSIZE)
#define ZT_PHY_MAX_INTERCEPTS ZT_PHY_MAX_SOCKETS
#define ZT_PHY_SOCKADDR_STORAGE_TYPE struct sockaddr_storage

#else // not Windows

#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>

//include msquic.h for quic protocol
#include <msquic.h>

#include "../node/InetAddress.hpp"
#include "../node/Metrics.hpp"
#include "../node/Mutex.hpp"

#if defined(__linux__) || defined(linux) || defined(__LINUX__) || defined(__linux)
#ifndef IPV6_DONTFRAG
#define IPV6_DONTFRAG 62
#endif
#endif

#define ZT_PHY_SOCKFD_TYPE int
#define ZT_PHY_SOCKFD_NULL (-1)
#define ZT_PHY_SOCKFD_VALID(s) ((s) > -1)
#define ZT_PHY_CLOSE_SOCKET(s) ::close(s)
#define ZT_PHY_MAX_SOCKETS (FD_SETSIZE)
#define ZT_PHY_MAX_INTERCEPTS ZT_PHY_MAX_SOCKETS
#define ZT_PHY_SOCKADDR_STORAGE_TYPE struct sockaddr_storage

#endif // Windows or not

namespace ZeroTier {

/**
 * Opaque socket type
 */
typedef void PhySocket;

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

//
// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
//
const QUIC_REGISTRATION_CONFIG QUICRegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

//
// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
//
const QUIC_BUFFER QUICAlpn = { sizeof("sample") - 1, (uint8_t*)"sample" };

//
// The default idle timeout period (1 second) used for the protocol.
//
const uint64_t QUICIdleTimeoutMs = 1000000000UL;

//
// The length of buffer sent over the streams in the protocol.
//
extern uint32_t QUICSendBufferSize;

//
// The QUIC API/function table returned from MsQuicOpen2. It contains all the
// functions called by the app to interact with MsQuic.
//
extern QUIC_API_TABLE* MsQuic;

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
extern HQUIC QUICRegistration;

extern unsigned int g_sock_id;
//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
extern HQUIC QUICConfigurationClient;
extern HQUIC QUICConfigurationServer;
extern char *sslKeyLogFile;

#define QUIC_STREAM

extern void
EncodeHexBuffer(
    _In_reads_(BufferLen) uint8_t* Buffer,
    _In_ uint8_t BufferLen,
    _Out_writes_bytes_(2*BufferLen) char* HexString
    );

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;
/**
 * Simple templated non-blocking sockets implementation
 *
 * Yes there is boost::asio and libuv, but I like small binaries and I hate
 * build dependencies. Both drag in a whole bunch of pasta with them.
 *
 * This class is templated on a pointer to a handler class which must
 * implement the following functions:
 *
 * For all platforms:
 *
 * phyOnDatagram(PhySocket *sock,void **uptr,const struct sockaddr *localAddr,const struct sockaddr *from,void *data,unsigned long len)
 * phyOnTcpConnect(PhySocket *sock,void **uptr,bool success)
 * phyOnTcpAccept(PhySocket *sockL,PhySocket *sockN,void **uptrL,void **uptrN,const struct sockaddr *from)
 * phyOnTcpClose(PhySocket *sock,void **uptr)
 * phyOnTcpData(PhySocket *sock,void **uptr,void *data,unsigned long len)
 * phyOnTcpWritable(PhySocket *sock,void **uptr)
 * phyOnFileDescriptorActivity(PhySocket *sock,void **uptr,bool readable,bool writable)
 *
 * On Linux/OSX/Unix only (not required/used on Windows or elsewhere):
 *
 * phyOnUnixAccept(PhySocket *sockL,PhySocket *sockN,void **uptrL,void **uptrN)
 * phyOnUnixClose(PhySocket *sock,void **uptr)
 * phyOnUnixData(PhySocket *sock,void **uptr,void *data,unsigned long len)
 * phyOnUnixWritable(PhySocket *sock,void **uptr)
 *
 * These templates typically refer to function objects. Templates are used to
 * avoid the call overhead of indirection, which is surprisingly high for high
 * bandwidth applications pushing a lot of packets.
 *
 * The 'sock' pointer above is an opaque pointer to a socket. Each socket
 * has a 'uptr' user-settable/modifiable pointer associated with it, which
 * can be set on bind/connect calls and is passed as a void ** to permit
 * resetting at any time. The ACCEPT handler takes two sets of sock and
 * uptr: sockL and uptrL for the listen socket, and sockN and uptrN for
 * the new TCP connection socket that has just been created.
 *
 * Handlers are always called. On outgoing TCP connection, CONNECT is always
 * called on either success or failure followed by DATA and/or WRITABLE as
 * indicated. On socket close, handlers are called unless close() is told
 * explicitly not to call handlers. It is safe to close a socket within a
 * handler, and in that case close() can be told not to call handlers to
 * prevent recursion.
 *
 * This isn't thread-safe with the exception of whack(), which is safe to
 * call from another thread to abort poll().
 */
template <typename HANDLER_PTR_TYPE>
class Phy
{
private:
	HANDLER_PTR_TYPE _handler;

	enum PhySocketType
	{
		ZT_PHY_SOCKET_CLOSED = 0x00, // socket is closed, will be removed on next poll()
		ZT_PHY_SOCKET_TCP_OUT_PENDING = 0x01,
		ZT_PHY_SOCKET_TCP_OUT_CONNECTED = 0x02,
		ZT_PHY_SOCKET_TCP_IN = 0x03,
		ZT_PHY_SOCKET_TCP_LISTEN = 0x04,
		ZT_PHY_SOCKET_UDP = 0x05,
		ZT_PHY_SOCKET_FD = 0x06,
		ZT_PHY_SOCKET_UNIX_IN = 0x07,
		ZT_PHY_SOCKET_UNIX_LISTEN = 0x08,
		ZT_PHY_SOCKET_QUIC_OUT_PENDING = 0x09,
		ZT_PHY_SOCKET_QUIC_OUT_CONNECTED = 0x0A,
		ZT_PHY_SOCKET_QUIC_IN = 0x0B,
		ZT_PHY_SOCKET_QUIC_LISTEN = 0x0C,
		ZT_PHY_SOCKET_QUIC_SHUTTINGDOWN = 0x0D,
	};

	enum ZT_QUIC_EVENTS_TYPE {
		ZT_QUIC_CLIENT_CONNECTION_EVENT = 1,
		ZT_QUIC_CLIENT_STREAM_EVENT,
		ZT_QUIC_SERVER_LISTENER_EVENT,
		ZT_QUIC_SERVER_CONNECTION_EVENT,
		ZT_QUIC_SERVER_STREAM_EVENT,
	};

	typedef QUIC_BUFFER SocketRawData;

	struct QUICSocketImpl {
		QUICSocketImpl(Phy *p) : type(ZT_PHY_SOCKET_CLOSED), connection(NULL), stream(NULL), s(NULL), phy(p),
		nreceived(0), sslKeyLogFile(NULL), maxDatagramSize(0), part_received(NULL),
		part_offset(0), ref_count(0) {
			id = __atomic_add_fetch(&g_sock_id, 1, __ATOMIC_SEQ_CST);
		}

		~QUICSocketImpl() {
			Mutex::Lock _l(qmutex);

			while (!queue.empty()) {
				SocketRawData *data = queue.front();
				free(data);
				queue.pop();
			}
			if (stream) {
				MsQuic->StreamClose(stream);
				stream = NULL;
				type = ZT_PHY_SOCKET_QUIC_SHUTTINGDOWN;
			}

			if (connection) {
				if (type == ZT_PHY_SOCKET_QUIC_LISTEN) {
					MsQuic->ListenerClose(connection);
					if (phy->_verbose) {
						int Port;
						char Host[1000];
						if (((struct sockaddr *)&saddr)->sa_family == AF_INET6) {
							struct sockaddr_in6 *addr = (struct  sockaddr_in6 *) &saddr;
							socklen_t Hlen = sizeof(Host);
							Port = ntohs(addr->sin6_port);
							inet_ntop(AF_INET6, &addr->sin6_addr.__in6_u, Host, Hlen);
						} else {
							struct sockaddr_in *addr = (struct  sockaddr_in *) &saddr;
							socklen_t Hlen = sizeof(Host);
							Port = ntohs(addr->sin_port);
							inet_ntop(AF_INET, &addr->sin_addr.s_addr, Host, Hlen);
						}
						
						printf("Closing QUIC Listener %s:%d\n", Host, Port);
					}
				} else {
					MsQuic->ConnectionClose(connection);
					//MsQuic->ConnectionShutdown((HQUIC)lpSock->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
				}
				connection = NULL;
			}

			type = ZT_PHY_SOCKET_CLOSED;
		}
		unsigned int id;
		PhySocketType type;
		HQUIC connection;
		HQUIC stream;
		PhySocket *s; // PhySocket pointer
		Phy *phy;
		std::queue<SocketRawData *> queue;
		Mutex qmutex;
		ZT_PHY_SOCKADDR_STORAGE_TYPE saddr; // remote for TCP_OUT and TCP_IN, local for TCP_LISTEN, RAW, and UDP
		uint64_t nreceived;
		QUIC_TLS_SECRETS TlsSecrets;
		char *sslKeyLogFile;
		int maxDatagramSize;
		SocketRawData *part_received;
		unsigned int part_offset;
		char length_buf[4];
		unsigned int ref_count;
	};

	typedef struct QUICReceivedData
	{
		PhySocket *s;
		QUICSocketImpl *quic;
		SocketRawData *data;
		ZT_PHY_SOCKADDR_STORAGE_TYPE to;
		ZT_PHY_SOCKADDR_STORAGE_TYPE from;
	}QUIC_RECEIVED_DATA, *LP_QUIC_RECEIVED_DATA;

	struct QUICEvent {
		QUICEvent(QUICSocketImpl *q, void *u, ZT_QUIC_EVENTS_TYPE t, int e): uptr(u), type(t), event(e) {
			this->quic = refQuicSocket(q);
		}
		~QUICEvent() {
			derefQuicSocket(quic);
		}
		QUICSocketImpl *quic;
		void *uptr;
		ZT_QUIC_EVENTS_TYPE type;
		int event;
	};

	struct PhySocketImpl {
		PhySocketImpl() : type(ZT_PHY_SOCKET_CLOSED), sock(-1), uptr(NULL), quic(NULL) {}
		PhySocketType type;
		ZT_PHY_SOCKFD_TYPE sock;
		void *uptr; // user-settable pointer
		ZT_PHY_SOCKADDR_STORAGE_TYPE saddr; // remote for TCP_OUT and TCP_IN, local for TCP_LISTEN, RAW, and UDP
		QUICSocketImpl *quic;
	};

	/*
	struct PhySocketImpl {
		PhySocketImpl(): id(__atomic_add_fetch(&g_sock_id, 1, __ATOMIC_SEQ_CST)), type(ZT_PHY_SOCKET_CLOSED), sock(-1), connection(0), stream(0), uptr(0), qmutex(0), nreceived(0), TlsSecrets({}), sslKeyLogFile(NULL), maxDatagramSize(0), part_received(NULL), part_offset(0) {}
		unsigned int id;
		PhySocketType type;
		ZT_PHY_SOCKFD_TYPE sock;
		void *connection;
		void *stream;
		void *uptr; // user-settable pointer
		std::queue<SocketRawData *> queue;
		Mutex *qmutex;
		ZT_PHY_SOCKADDR_STORAGE_TYPE saddr; // remote for TCP_OUT and TCP_IN, local for TCP_LISTEN, RAW, and UDP
		//ZT_PHY_SOCKADDR_STORAGE_TYPE listener_saddr; // remote for TCP_OUT and TCP_IN, local for TCP_LISTEN, RAW, and UDP
		uint64_t nreceived;
		QUIC_TLS_SECRETS TlsSecrets;
		char *sslKeyLogFile;
		int maxDatagramSize;
		SocketRawData *part_received;
		unsigned int part_offset;
		char length_buf[4];
	};
	*/

	std::list<PhySocketImpl> _socks;
	fd_set _readfds;
	fd_set _writefds;
	std::queue<LP_QUIC_RECEIVED_DATA> _pqueue;
	Mutex _pmutex;
	std::queue<QUICEvent *> _equeue;
	Mutex _emutex;
#if defined(_WIN32) || defined(_WIN64)
	fd_set _exceptfds;
#endif
	long _nfds;

	ZT_PHY_SOCKFD_TYPE _whackReceiveSocket;
	ZT_PHY_SOCKFD_TYPE _whackSendSocket;

	bool _noDelay;
	bool _noCheck;
	bool _verbose;
	char *_publicIp;
	int _primaryPort;
	ZT_PHY_SOCKADDR_STORAGE_TYPE _publicAddress;

public:
	/**
	 * @param handler Pointer of type HANDLER_PTR_TYPE to handler
	 * @param noDelay If true, disable TCP NAGLE algorithm on TCP sockets
	 * @param noCheck If true, attempt to set UDP SO_NO_CHECK option to disable sending checksums
	 */
	Phy(HANDLER_PTR_TYPE handler,bool noDelay,bool noCheck) :
		_handler(handler),
		_verbose(false),
		_publicIp(NULL)
	{
		FD_ZERO(&_readfds);
		FD_ZERO(&_writefds);

#if defined(_WIN32) || defined(_WIN64)
		FD_ZERO(&_exceptfds);

		SOCKET pipes[2];
		{	// hack copied from StackOverflow, behaves a bit like pipe() on *nix systems
			struct sockaddr_in inaddr;
			struct sockaddr addr;
			SOCKET lst=::socket(AF_INET, SOCK_STREAM,IPPROTO_TCP);
			if (lst == INVALID_SOCKET)
				throw std::runtime_error("unable to create pipes for select() abort");
			memset(&inaddr, 0, sizeof(inaddr));
			memset(&addr, 0, sizeof(addr));
			inaddr.sin_family = AF_INET;
			inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			inaddr.sin_port = 0;
			int yes=1;
			setsockopt(lst,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));
			bind(lst,(struct sockaddr *)&inaddr,sizeof(inaddr));
			listen(lst,1);
			int len=sizeof(inaddr);
			getsockname(lst, &addr,&len);
			pipes[0]=::socket(AF_INET, SOCK_STREAM,0);
			if (pipes[0] == INVALID_SOCKET)
				throw std::runtime_error("unable to create pipes for select() abort");
			connect(pipes[0],&addr,len);
			pipes[1]=accept(lst,0,0);
			closesocket(lst);
		}
#else // not Windows
		int pipes[2];
		if (::pipe(pipes))
			throw std::runtime_error("unable to create pipes for select() abort");
#endif // Windows or not

		_nfds = (pipes[0] > pipes[1]) ? (long)pipes[0] : (long)pipes[1];
		_whackReceiveSocket = pipes[0];
		_whackSendSocket = pipes[1];
		fcntl(_whackReceiveSocket, F_SETFL, O_NONBLOCK);
		fcntl(_whackSendSocket, F_SETFL, O_NONBLOCK);
		FD_SET(_whackReceiveSocket, &_readfds);
		_noDelay = noDelay;
		_noCheck = noCheck;
		_primaryPort = 0;
	}

	~Phy()
	{
		for(typename std::list<PhySocketImpl>::const_iterator s(_socks.begin());s!=_socks.end();++s) {
			if (s->type != ZT_PHY_SOCKET_CLOSED) {
				this->close((PhySocket *)&(*s),true);
			}
		}
		ZT_PHY_CLOSE_SOCKET(_whackReceiveSocket);
		ZT_PHY_CLOSE_SOCKET(_whackSendSocket);
	}

	static QUICSocketImpl *refQuicSocket(QUICSocketImpl *lpSock) {
		if (lpSock)
			__atomic_add_fetch(&lpSock->ref_count, 1, __ATOMIC_SEQ_CST);
		return lpSock;
	}

	static void derefQuicSocket(QUICSocketImpl *lpSock) {
		if (lpSock && !__atomic_sub_fetch(&lpSock->ref_count, 1, __ATOMIC_SEQ_CST)) {
        	delete lpSock;
    	}
	}

	inline void setVerbose(bool v) { _verbose = v; }
	inline void setPublicIp(const char *ip) 
	{ 
		_publicIp = (char *)ip;
		if (ip) {
			struct addrinfo *result = NULL;
			int err = getaddrinfo(ip, NULL, NULL, &result) ;
			if(err)
			{
				if (err == EAI_SYSTEM)
						fprintf(stderr, "Error resolving %s : %s\n", ip,  strerror(errno));
				else
						fprintf(stderr, "Error resolving %s : %s\n", ip,  gai_strerror(err));
				return;
			}
			memcpy(&_publicAddress, result->ai_addr, result->ai_addrlen);
			freeaddrinfo(result);
		}
	}

	inline void setPrimaryPort(int p) 
	{ 
		_primaryPort = p; 
		if (((struct  sockaddr *)&_publicAddress)->sa_family == AF_INET)
		{
			struct sockaddr_in *addr = (struct sockaddr_in *)&_publicAddress;
			addr->sin_port = htons(p);
		}
		else
		{
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&_publicAddress;
			addr->sin6_port = htons(p);
		}
	}

	/**
	 * @param s Socket object
	 * @return Underlying OS-type (usually int or long) file descriptor associated with object
	 */
	static inline ZT_PHY_SOCKFD_TYPE getDescriptor(PhySocket* s) throw()
	{
		return reinterpret_cast<PhySocketImpl*>(s)->sock;
	}

	/**
	 * @param s Socket object
	 * @return Pointer to user object
	 */
	static inline void** getuptr(PhySocket* s) throw()
	{
		return &(reinterpret_cast<PhySocketImpl*>(s)->uptr);
	}

	/**
	 * Cause poll() to stop waiting immediately
	 *
	 * This can be used to reset the polling loop after changes that require
	 * attention, or to shut down a background thread that is waiting, etc.
	 */
	inline void whack()
	{
#if defined(_WIN32) || defined(_WIN64)
		::send(_whackSendSocket, (const char*)this, 1, 0);
#else
		(void)(::write(_whackSendSocket, (PhySocket*)this, 1));
#endif
	}

	/**
	 * @return Number of open sockets
	 */
	inline unsigned long count() const throw()
	{
		return _socks.size();
	}

	/**
	 * @return Maximum number of sockets allowed
	 */
	inline unsigned long maxCount() const throw()
	{
		return ZT_PHY_MAX_SOCKETS;
	}

	/**
	 * Wrap a raw file descriptor in a PhySocket structure
	 *
	 * This can be used to select/poll on a raw file descriptor as part of this
	 * class's I/O loop. By default the fd is set for read notification but
	 * this can be controlled with setNotifyReadable(). When any detected
	 * condition is present, the phyOnFileDescriptorActivity() callback is
	 * called with one or both of its arguments 'true'.
	 *
	 * The Phy<>::close() method *must* be called when you're done with this
	 * file descriptor to remove it from the select/poll set, but unlike other
	 * types of sockets Phy<> does not actually close the underlying fd or
	 * otherwise manage its life cycle. There is also no close notification
	 * callback for this fd, since Phy<> doesn't actually perform reading or
	 * writing or detect error conditions. This is only useful for adding a
	 * file descriptor to Phy<> to select/poll on it.
	 *
	 * @param fd Raw file descriptor
	 * @param uptr User pointer to supply to callbacks
	 * @return PhySocket wrapping fd or NULL on failure (out of memory or too many sockets)
	 */
	inline PhySocket *wrapSocket(ZT_PHY_SOCKFD_TYPE fd,void *uptr = (void *)0)
	{
		if (_socks.size() >= ZT_PHY_MAX_SOCKETS)
			return (PhySocket *)0;
		try {
			_socks.push_back(PhySocketImpl());
		} catch ( ... ) {
			return (PhySocket *)0;
		}
		PhySocketImpl &sws = _socks.back();
		if ((long)fd > _nfds)
			_nfds = (long)fd;
		FD_SET(fd,&_readfds);
		sws.type = ZT_PHY_SOCKET_UNIX_IN; /* TODO: Type was changed to allow for CBs with new RPC model */
		sws.sock = fd;
		sws.uptr = uptr;
		memset(&(sws.saddr),0,sizeof(struct sockaddr_storage));
		// no sockaddr for this socket type, leave saddr null
		return (PhySocket *)&sws;
	}

	/**
	 * Bind a UDP socket
	 *
	 * @param localAddress Local endpoint address and port
	 * @param uptr Initial value of user pointer associated with this socket (default: NULL)
	 * @param bufferSize Desired socket receive/send buffer size -- will set as close to this as possible (default: 0, leave alone)
	 * @return Socket or NULL on failure to bind
	 */
	inline PhySocket *udpBind(const struct sockaddr *localAddress,void *uptr = (void *)0,int bufferSize = 0)
	{
		if (_socks.size() >= ZT_PHY_MAX_SOCKETS)
			return (PhySocket *)0;

		ZT_PHY_SOCKFD_TYPE s = ::socket(localAddress->sa_family,SOCK_DGRAM,0);
		if (!ZT_PHY_SOCKFD_VALID(s))
			return (PhySocket *)0;

		if (bufferSize > 0) {
			int bs = bufferSize;
			while (bs >= 65536) {
				int tmpbs = bs;
				if (setsockopt(s,SOL_SOCKET,SO_RCVBUF,(const char *)&tmpbs,sizeof(tmpbs)) == 0)
					break;
				bs -= 4096;
			}
			bs = bufferSize;
			while (bs >= 65536) {
				int tmpbs = bs;
				if (setsockopt(s,SOL_SOCKET,SO_SNDBUF,(const char *)&tmpbs,sizeof(tmpbs)) == 0)
					break;
				bs -= 4096;
			}
		}

#if defined(_WIN32) || defined(_WIN64)
		{
			BOOL f;
			if (localAddress->sa_family == AF_INET6) {
				f = TRUE; setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,(const char *)&f,sizeof(f));
				f = FALSE; setsockopt(s,IPPROTO_IPV6,IPV6_DONTFRAG,(const char *)&f,sizeof(f));
			}
			f = FALSE; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(const char *)&f,sizeof(f));
			f = TRUE; setsockopt(s,SOL_SOCKET,SO_BROADCAST,(const char *)&f,sizeof(f));
		}
#else // not Windows
		{
			int f;
			if (localAddress->sa_family == AF_INET6) {
				f = 1; setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,(void *)&f,sizeof(f));
#ifdef IPV6_MTU_DISCOVER
				f = 0; setsockopt(s,IPPROTO_IPV6,IPV6_MTU_DISCOVER,&f,sizeof(f));
#endif
#ifdef IPV6_DONTFRAG
				f = 0; setsockopt(s,IPPROTO_IPV6,IPV6_DONTFRAG,&f,sizeof(f));
#endif
			}
			f = 0; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(void *)&f,sizeof(f));
			f = 1; setsockopt(s,SOL_SOCKET,SO_BROADCAST,(void *)&f,sizeof(f));
#ifdef IP_DONTFRAG
			f = 0; setsockopt(s,IPPROTO_IP,IP_DONTFRAG,&f,sizeof(f));
#endif
#ifdef IP_MTU_DISCOVER
			f = 0; setsockopt(s,IPPROTO_IP,IP_MTU_DISCOVER,&f,sizeof(f));
#endif
#ifdef SO_NO_CHECK
			// For now at least we only set SO_NO_CHECK on IPv4 sockets since some
			// IPv6 stacks incorrectly discard zero checksum packets. May remove
			// this restriction later once broken stuff dies more.
			if ((localAddress->sa_family == AF_INET)&&(_noCheck)) {
				f = 1; setsockopt(s,SOL_SOCKET,SO_NO_CHECK,(void *)&f,sizeof(f));
			}
#endif
		}
#endif // Windows or not
		/*
		int Port;
		char Host[1000];
		if (localAddress->sa_family == AF_INET6) {
			struct sockaddr_in6 *addr = (struct  sockaddr_in6 *) localAddress;
			socklen_t Hlen = sizeof(Host);
			Port = ntohs(addr->sin6_port);
			inet_ntop(localAddress->sa_family, &addr->sin6_addr.__in6_u, Host, Hlen);
		} else {
			struct sockaddr_in *addr = (struct  sockaddr_in *) localAddress;
			socklen_t Hlen = sizeof(Host);
			Port = ntohs(addr->sin_port);
			inet_ntop(localAddress->sa_family, &addr->sin_addr.s_addr, Host, Hlen);
		}
		
		printf("Binding UDP %s:%d\n", Host, Port);
		*/

		if (::bind(s,localAddress,(localAddress->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))<0) {
			fprintf(stderr, "Couldn't bind UDP. Error %d\n", errno);
			ZT_PHY_CLOSE_SOCKET(s);
			return (PhySocket *)0;
		}

#if defined(_WIN32) || defined(_WIN64)
		{ u_long iMode=1; ioctlsocket(s,FIONBIO,&iMode); }
#else
		fcntl(s,F_SETFL,O_NONBLOCK);
#endif

		try {
			_socks.push_back(PhySocketImpl());
		} catch ( ... ) {
			ZT_PHY_CLOSE_SOCKET(s);
			return (PhySocket *)0;
		}
		PhySocketImpl &sws = _socks.back();

		if ((long)s > _nfds)
			_nfds = (long)s;
		FD_SET(s,&_readfds);
		sws.type = ZT_PHY_SOCKET_UDP;
		sws.sock = s;
		sws.uptr = uptr;
		memset(&(sws.saddr),0,sizeof(struct sockaddr_storage));
		memcpy(&(sws.saddr),localAddress,(localAddress->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));

		return (PhySocket *)&sws;
	}

	/**
	 * Set the IP TTL for the next outgoing packet (for IPv4 UDP sockets only)
	 *
	 * @param ttl New TTL (0 or >255 will set it to 255)
	 * @return True on success
	 */
	inline bool setIp4UdpTtl(PhySocket *sock,unsigned int ttl)
	{
		PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(sock));
#if defined(_WIN32) || defined(_WIN64)
		DWORD tmp = ((ttl == 0)||(ttl > 255)) ? 255 : (DWORD)ttl;
		return (::setsockopt(sws.sock,IPPROTO_IP,IP_TTL,(const char *)&tmp,sizeof(tmp)) == 0);
#else
		int tmp = ((ttl == 0)||(ttl > 255)) ? 255 : (int)ttl;
		return (::setsockopt(sws.sock,IPPROTO_IP,IP_TTL,(void *)&tmp,sizeof(tmp)) == 0);
#endif
	}

	/**
	 * Send a UDP packet
	 *
	 * @param sock UDP socket
	 * @param remoteAddress Destination address (must be correct type for socket)
	 * @param data Data to send
	 * @param len Length of packet
	 * @return True if packet appears to have been sent successfully
	 */
	inline bool udpSend(PhySocket *sock,const struct sockaddr *remoteAddress,const void *data,unsigned long len)
	{
		PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(sock));
		bool sent = false;
#if defined(_WIN32) || defined(_WIN64)
		sent = ((long)::sendto(
				sws.sock,
				reinterpret_cast<const char *>(data),
				len,
				0,
				remoteAddress,
				(remoteAddress->sa_family == AF_INET6) ? 
					sizeof(struct sockaddr_in6) : 
					sizeof(struct sockaddr_in)) == (long)len);
#else
		sent = ((long)::sendto(
				sws.sock,
				data,
				len,
				0,
				remoteAddress,
				(remoteAddress->sa_family == AF_INET6) ? 
					sizeof(struct sockaddr_in6) : 
				 	sizeof(struct sockaddr_in)) == (long)len);
#endif
		if (sent) {
			Metrics::udp_send += len;
		}

		return sent;
	}

#ifdef __UNIX_LIKE__
	/**
	 * Listen for connections on a Unix domain socket
	 *
	 * @param path Path to Unix domain socket
	 * @param uptr Arbitrary pointer to associate
	 * @return PhySocket or NULL if cannot bind
	 */
	inline PhySocket *unixListen(const char *path,void *uptr = (void *)0)
	{
		struct sockaddr_un sun;

		if (_socks.size() >= ZT_PHY_MAX_SOCKETS)
			return (PhySocket *)0;

		memset(&sun,0,sizeof(sun));
		sun.sun_family = AF_UNIX;
		if (strlen(path) >= sizeof(sun.sun_path))
			return (PhySocket *)0;
		strcpy(sun.sun_path,path);

		ZT_PHY_SOCKFD_TYPE s = ::socket(PF_UNIX,SOCK_STREAM,0);
		if (!ZT_PHY_SOCKFD_VALID(s))
			return (PhySocket *)0;

		::fcntl(s,F_SETFL,O_NONBLOCK);

		::unlink(path);
		if (::bind(s,(struct sockaddr *)&sun,sizeof(struct sockaddr_un)) != 0) {
			ZT_PHY_CLOSE_SOCKET(s);
			return (PhySocket *)0;
		}
		if (::listen(s,128) != 0) {
			ZT_PHY_CLOSE_SOCKET(s);
			return (PhySocket *)0;
		}

		try {
			_socks.push_back(PhySocketImpl());
		} catch ( ... ) {
			ZT_PHY_CLOSE_SOCKET(s);
			return (PhySocket *)0;
		}
		PhySocketImpl &sws = _socks.back();

		if ((long)s > _nfds)
			_nfds = (long)s;
		FD_SET(s,&_readfds);
		sws.type = ZT_PHY_SOCKET_UNIX_LISTEN;
		sws.sock = s;
		sws.uptr = uptr;
		memset(&(sws.saddr),0,sizeof(struct sockaddr_storage));
		memcpy(&(sws.saddr),&sun,sizeof(struct sockaddr_un));

		return (PhySocket *)&sws;
	}
#endif // __UNIX_LIKE__

	/**
	 * Bind a local listen socket to listen for new TCP connections
	 *
	 * @param localAddress Local address and port
	 * @param uptr Initial value of uptr for new socket (default: NULL)
	 * @return Socket or NULL on failure to bind
	 */
	inline PhySocket *tcpListen(const struct sockaddr *localAddress,void *uptr = (void *)0)
	{
		if (_socks.size() >= ZT_PHY_MAX_SOCKETS)
			return (PhySocket *)0;

		ZT_PHY_SOCKFD_TYPE s = ::socket(localAddress->sa_family,SOCK_STREAM,0);
		if (!ZT_PHY_SOCKFD_VALID(s))
			return (PhySocket *)0;

#if defined(_WIN32) || defined(_WIN64)
		{
			BOOL f;
			f = TRUE; ::setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,(const char *)&f,sizeof(f));
			f = TRUE; ::setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(const char *)&f,sizeof(f));
			f = (_noDelay ? TRUE : FALSE); setsockopt(s,IPPROTO_TCP,TCP_NODELAY,(char *)&f,sizeof(f));
			u_long iMode=1;
			ioctlsocket(s,FIONBIO,&iMode);
		}
#else
		{
			int f;
			f = 1; ::setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,(void *)&f,sizeof(f));
			f = 1; ::setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(void *)&f,sizeof(f));
			f = (_noDelay ? 1 : 0); setsockopt(s,IPPROTO_TCP,TCP_NODELAY,(char *)&f,sizeof(f));
			fcntl(s,F_SETFL,O_NONBLOCK);
		}
#endif
		/*
		int Port;
		char Host[1000];
		if (localAddress->sa_family == AF_INET6) {
			struct sockaddr_in6 *addr = (struct  sockaddr_in6 *) localAddress;
			socklen_t Hlen = sizeof(Host);
			Port = ntohs(addr->sin6_port);
			inet_ntop(localAddress->sa_family, &addr->sin6_addr.__in6_u, Host, Hlen);
		} else {
			struct sockaddr_in *addr = (struct  sockaddr_in *) localAddress;
			socklen_t Hlen = sizeof(Host);
			Port = ntohs(addr->sin_port);
			inet_ntop(localAddress->sa_family, &addr->sin_addr.s_addr, Host, Hlen);
		}
		
		printf("Binding TCP %s:%d\n", Host, Port);
		*/

		if (::bind(s,localAddress,(localAddress->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))<0) {
			fprintf(stderr, "Couldn't bind TCP. Error %d\n", errno);
			ZT_PHY_CLOSE_SOCKET(s);
			return (PhySocket *)0;
		}

		if (::listen(s,1024)<0) {
			fprintf(stderr, "Couldn't listen TCP. Error %d\n", errno);
			ZT_PHY_CLOSE_SOCKET(s);
			return (PhySocket *)0;
		}

		try {
			_socks.push_back(PhySocketImpl());
		} catch ( ... ) {
			ZT_PHY_CLOSE_SOCKET(s);
			return (PhySocket *)0;
		}
		PhySocketImpl &sws = _socks.back();

		if ((long)s > _nfds)
			_nfds = (long)s;
		FD_SET(s,&_readfds);
		sws.type = ZT_PHY_SOCKET_TCP_LISTEN;
		sws.sock = s;
		sws.uptr = uptr;
		memset(&(sws.saddr),0,sizeof(struct sockaddr_storage));
		memcpy(&(sws.saddr),localAddress,(localAddress->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));

		return (PhySocket *)&sws;
	}

	/**
	 * Start a non-blocking connect; CONNECT handler is called on success or failure
	 *
	 * A return value of NULL indicates a synchronous failure such as a
	 * failure to open a socket. The TCP connection handler is not called
	 * in this case.
	 *
	 * It is possible on some platforms for an "instant connect" to occur,
	 * such as when connecting to a loopback address. In this case, the
	 * 'connected' result parameter will be set to 'true' and if the
	 * 'callConnectHandler' flag is true (the default) the TCP connect
	 * handler will be called before the function returns.
	 *
	 * These semantics can be a bit confusing, but they're less so than
	 * the underlying semantics of asynchronous TCP connect.
	 *
	 * @param remoteAddress Remote address
	 * @param connected Result parameter: set to whether an "instant connect" has occurred (true if yes)
	 * @param uptr Initial value of uptr for new socket (default: NULL)
	 * @param callConnectHandler If true, call TCP connect handler even if result is known before function exit (default: true)
	 * @return New socket or NULL on failure
	 */
	inline PhySocket *tcpConnect(const struct sockaddr *remoteAddress,bool &connected,void *uptr = (void *)0,bool callConnectHandler = true)
	{
		if (_socks.size() >= ZT_PHY_MAX_SOCKETS)
			return (PhySocket *)0;

		ZT_PHY_SOCKFD_TYPE s = ::socket(remoteAddress->sa_family,SOCK_STREAM,0);
		if (!ZT_PHY_SOCKFD_VALID(s)) {
			connected = false;
			return (PhySocket *)0;
		}

#if defined(_WIN32) || defined(_WIN64)
		{
			BOOL f;
			if (remoteAddress->sa_family == AF_INET6) { f = TRUE; ::setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,(const char *)&f,sizeof(f)); }
			f = TRUE; ::setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(const char *)&f,sizeof(f));
			f = (_noDelay ? TRUE : FALSE); setsockopt(s,IPPROTO_TCP,TCP_NODELAY,(char *)&f,sizeof(f));
			u_long iMode=1;
			ioctlsocket(s,FIONBIO,&iMode);
		}
#else
		{
			int f;
			if (remoteAddress->sa_family == AF_INET6) { f = 1; ::setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,(void *)&f,sizeof(f)); }
			f = 1; ::setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(void *)&f,sizeof(f));
			f = (_noDelay ? 1 : 0); setsockopt(s,IPPROTO_TCP,TCP_NODELAY,(char *)&f,sizeof(f));
			fcntl(s,F_SETFL,O_NONBLOCK);
		}
#endif

		connected = true;
		if (::connect(s,remoteAddress,(remoteAddress->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))) {
			connected = false;
#if defined(_WIN32) || defined(_WIN64)
			if (WSAGetLastError() != WSAEWOULDBLOCK) {
#else
			if (errno != EINPROGRESS) {
#endif
				ZT_PHY_CLOSE_SOCKET(s);
				return (PhySocket *)0;
			} // else connection is proceeding asynchronously...
		}

		try {
			_socks.push_back(PhySocketImpl());
		} catch ( ... ) {
			ZT_PHY_CLOSE_SOCKET(s);
			return (PhySocket *)0;
		}
		PhySocketImpl &sws = _socks.back();

		if ((long)s > _nfds)
			_nfds = (long)s;
		if (connected) {
			FD_SET(s,&_readfds);
			sws.type = ZT_PHY_SOCKET_TCP_OUT_CONNECTED;
		} else {
			FD_SET(s,&_writefds);
#if defined(_WIN32) || defined(_WIN64)
			FD_SET(s,&_exceptfds);
#endif
			sws.type = ZT_PHY_SOCKET_TCP_OUT_PENDING;
		}
		sws.sock = s;
		sws.uptr = uptr;
		memset(&(sws.saddr),0,sizeof(struct sockaddr_storage));
		memcpy(&(sws.saddr),remoteAddress,(remoteAddress->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));

		if ((callConnectHandler)&&(connected)) {
			try {
				_handler->phyOnTcpConnect((PhySocket *)&sws,&(sws.uptr),true);
			} catch ( ... ) {}
		}

		return (PhySocket *)&sws;
	}

	/**
	 * Try to set buffer sizes as close to the given value as possible
	 *
	 * This will try the specified value and then lower values in 16K increments
	 * until one works.
	 *
	 * @param sock Socket
	 * @param receiveBufferSize Desired size of receive buffer
	 * @param sendBufferSize Desired size of send buffer
	 */
	inline void setBufferSizes(const PhySocket *sock,int receiveBufferSize,int sendBufferSize)
	{
		PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(sock));
		if (receiveBufferSize > 0) {
			while (receiveBufferSize > 0) {
				int tmpbs = receiveBufferSize;
				if (::setsockopt(sws.sock,SOL_SOCKET,SO_RCVBUF,(const char *)&tmpbs,sizeof(tmpbs)) == 0)
					break;
				receiveBufferSize -= 16384;
			}
		}
		if (sendBufferSize > 0) {
			while (sendBufferSize > 0) {
				int tmpbs = sendBufferSize;
				if (::setsockopt(sws.sock,SOL_SOCKET,SO_SNDBUF,(const char *)&tmpbs,sizeof(tmpbs)) == 0)
					break;
				sendBufferSize -= 16384;
			}
		}
	}

	/**
	 * Attempt to send data to a stream socket (non-blocking)
	 *
	 * If -1 is returned, the socket should no longer be used as it is now
	 * destroyed. If callCloseHandler is true, the close handler will be
	 * called before the function returns.
	 *
	 * This can be used with TCP, Unix, or socket pair sockets.
	 *
	 * @param sock An open stream socket (other socket types will fail)
	 * @param data Data to send
	 * @param len Length of data
	 * @param callCloseHandler If true, call close handler on socket closing failure condition (default: true)
	 * @return Number of bytes actually sent or -1 on fatal error (socket closure)
	 */
	inline long streamSend(PhySocket *sock,const void *data,unsigned long len,bool callCloseHandler = true)
	{
		PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(sock));
#if defined(_WIN32) || defined(_WIN64)
		long n = (long)::send(sws.sock,reinterpret_cast<const char *>(data),len,0);
		if (n == SOCKET_ERROR) {
				switch(WSAGetLastError()) {
					case WSAEINTR:
					case WSAEWOULDBLOCK:
						return 0;
					default:
						this->close(sock,callCloseHandler);
						return -1;
				}
		}
#else // not Windows
		long n = (long)::send(sws.sock,data,len,0);
		if (n < 0) {
			switch(errno) {
#ifdef EAGAIN
				case EAGAIN:
#endif
#if defined(EWOULDBLOCK) && ( !defined(EAGAIN) || (EWOULDBLOCK != EAGAIN) )
				case EWOULDBLOCK:
#endif
#ifdef EINTR
				case EINTR:
#endif
					return 0;
				default:
					this->close(sock,callCloseHandler);
					return -1;
			}
		}
#endif // Windows or not
		return n;
	}

#ifdef __UNIX_LIKE__
	/**
	 * Attempt to send data to a Unix domain socket connection (non-blocking)
	 *
	 * If -1 is returned, the socket should no longer be used as it is now
	 * destroyed. If callCloseHandler is true, the close handler will be
	 * called before the function returns.
	 *
	 * @param sock An open Unix socket (other socket types will fail)
	 * @param data Data to send
	 * @param len Length of data
	 * @param callCloseHandler If true, call close handler on socket closing failure condition (default: true)
	 * @return Number of bytes actually sent or -1 on fatal error (socket closure)
	 */
	inline long unixSend(PhySocket *sock,const void *data,unsigned long len,bool callCloseHandler = true)
	{
		PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(sock));
		long n = (long)::write(sws.sock,data,len);
		if (n < 0) {
			switch(errno) {
#ifdef EAGAIN
				case EAGAIN:
#endif
#if defined(EWOULDBLOCK) && ( !defined(EAGAIN) || (EWOULDBLOCK != EAGAIN) )
				case EWOULDBLOCK:
#endif
#ifdef EINTR
				case EINTR:
#endif
					return 0;
				default:
					this->close(sock,callCloseHandler);
					return -1;
			}
		}
		return n;
	}
#endif // __UNIX_LIKE__

	/**
	 * For streams, sets whether we want to be notified that the socket is writable
	 *
	 * This can be used with TCP, Unix, or socket pair sockets.
	 *
	 * Call whack() if this is being done from another thread and you want
	 * it to take effect immediately. Otherwise it is only guaranteed to
	 * take effect on the next poll().
	 *
	 * @param sock Stream connection socket
	 * @param notifyWritable Want writable notifications?
	 */
	inline void setNotifyWritable(PhySocket *sock,bool notifyWritable)
	{
		PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(sock));
		if (notifyWritable) {
			FD_SET(sws.sock,&_writefds);
		} else {
			FD_CLR(sws.sock,&_writefds);
		}
	}

	/**
	 * Set whether we want to be notified that a socket is readable
	 *
	 * This is primarily for raw sockets added with wrapSocket(). It could be
	 * used with others, but doing so would essentially lock them and prevent
	 * data from being read from them until this is set to 'true' again.
	 *
	 * @param sock Socket to modify
	 * @param notifyReadable True if socket should be monitored for readability
	 */
	inline void setNotifyReadable(PhySocket *sock,bool notifyReadable)
	{
		PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(sock));
		if (notifyReadable) {
			FD_SET(sws.sock,&_readfds);
		} else {
			FD_CLR(sws.sock,&_readfds);
		}
	}

	inline bool quicInit()
	{
		if (MsQuic)
			return true;
		
		QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

		//
		// Open a handle to the library and get the API function table.
		//
		if (QUIC_FAILED(Status = MsQuicOpen2((const QUIC_API_TABLE **)&MsQuic))) {
			fprintf(stderr, "MsQuicOpen2 failed, 0x%x!\n", Status);
			goto Error;
		}

		//
		// Create a registration for the app's connections.
		//
		if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&QUICRegConfig, &QUICRegistration))) {
			fprintf(stderr, "RegistrationOpen failed, 0x%x!\n", Status);
			goto Error;
		}

		return true;
Error:
		if (MsQuic != NULL) {
			if (QUICConfigurationClient != NULL) {
				MsQuic->ConfigurationClose(QUICConfigurationClient);
			}
			if (QUICConfigurationServer != NULL) {
				MsQuic->ConfigurationClose(QUICConfigurationServer);
			}
			if (QUICRegistration != NULL) {
				//
				// This will block until all outstanding child objects have been
				// closed.
				//
				MsQuic->RegistrationClose(QUICRegistration);
			}
			MsQuicClose(MsQuic);
		}

		return false;
	}

	inline void quicOnData(PhySocket *s, SocketRawData *data, QUICSocketImpl *quic, ZT_PHY_SOCKADDR_STORAGE_TYPE *from, ZT_PHY_SOCKADDR_STORAGE_TYPE *to )
	{
		LP_QUIC_RECEIVED_DATA rdata = (LP_QUIC_RECEIVED_DATA)malloc(sizeof(QUIC_RECEIVED_DATA));
		rdata->data = data;
		rdata->s = s;
		rdata->quic = refQuicSocket(quic);
		memcpy(&rdata->from, from, sizeof(rdata->from));
		memcpy(&rdata->to, to, sizeof(rdata->to));

		_pmutex.lock();
		_pqueue.push(rdata);
		_pmutex.unlock();
		whack();
	}

	inline void quicExecClientStreamEvents(QUICSocketImpl *q, void *uptr, QUIC_STREAM_EVENT_TYPE event)
	{
		switch (event) {
		case QUIC_STREAM_EVENT_SEND_COMPLETE:
			//
			// A previous StreamSend call has completed, and the context is being
			// returned back to the app.
			//
			free(uptr);
			//if (phy->_verbose)
			//	printf("[strm][%p] Data sent\n", Stream);
			break;
		case QUIC_STREAM_EVENT_RECEIVE:
			//
			// Data was received from the peer on the stream.
			//
			break;
		case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
			//
			// The peer gracefully shut down its send direction of the stream.
			//
			if (_verbose)
				printf("[strm][%p] Peer aborted\n", q->stream);
			break;
		case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
			//
			// The peer aborted its send direction of the stream.
			//
			if (_verbose)
				printf("[strm][%p] Peer shut down\n", q->stream);
			break;
		case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
			//
			// Both directions of the stream have been shut down and MsQuic is done
			// with the stream. It can now be safely cleaned up.
			//
			if (_verbose)
				printf("[strm][%p] All done\n", q->stream);
			{
				BOOLEAN AppCloseInProgress = (BOOLEAN)(uintptr_t)uptr;
				if (!AppCloseInProgress) {
					Phy::quicShutdown(q);
				}
			}
			break;
		default:
			break;
		}
	}

	//
	// The clients's callback for stream events from MsQuic.
	//
	_IRQL_requires_max_(DISPATCH_LEVEL)
	_Function_class_(QUIC_STREAM_CALLBACK)

	static
	QUIC_STATUS
	QUIC_API
	QUICClientStreamCallback(
		_In_ HQUIC Stream,
		_In_opt_ void* Context,
		_Inout_ QUIC_STREAM_EVENT* Event
		)
	{
		//UNREFERENCED_PARAMETER(Context);
		QUICSocketImpl *lpSock = (QUICSocketImpl *)Context;
		switch (Event->Type) {
		case QUIC_STREAM_EVENT_SEND_COMPLETE:
			//
			// A previous StreamSend call has completed, and the context is being
			// returned back to the app.
			//
			free(Event->SEND_COMPLETE.ClientContext);
			//if (phy->_verbose)
			//	printf("[strm][%p] Data sent\n", Stream);
			break;
		case QUIC_STREAM_EVENT_RECEIVE:
			//
			// Data was received from the peer on the stream.
			//
			{
                uint32_t i;
                for (i=0; i<Event->RECEIVE.BufferCount; i++) {
                    QUIC_BUFFER qb = Event->RECEIVE.Buffers[i];
					unsigned int Len = qb.Length;
					uint8_t *Buf = qb.Buffer;
					do {
						if (lpSock->part_received) {
							unsigned int length = Len;
							unsigned int rem = lpSock->part_received->Length - (lpSock->part_offset - sizeof(length));

							if (length > rem) {
								length = rem;
							}
							
							if (lpSock->phy->_verbose)
								printf("Pkt len = %u current = %u. Need length %u - rem %u to complete remaining packet %u\n", lpSock->part_received->Length, lpSock->part_offset - sizeof(length), length, rem, Len);
							
							memcpy(lpSock->part_received->Buffer+lpSock->part_offset-sizeof(length), Buf, length);
							lpSock->part_offset += length;
							Len -= length;
							Buf += length;

							if (lpSock->part_offset - sizeof(length) == lpSock->part_received->Length) {
								lpSock->phy->quicOnData(lpSock->s, lpSock->part_received, lpSock, &lpSock->saddr, &lpSock->saddr);
								lpSock->part_received = NULL;
								lpSock->part_offset = 0;
							}

						} else {
							unsigned int length = 0;
							if (lpSock->part_offset + Len >= sizeof(length)) {
								if (lpSock->part_offset < sizeof(length)) {
									unsigned int rem = sizeof(length) - lpSock->part_offset;
									memcpy(lpSock->length_buf+lpSock->part_offset, Buf, rem);
									memcpy(&length, lpSock->length_buf, sizeof(length));
									lpSock->part_offset += rem;
									Len -= rem;
									Buf += rem;
								}

								if (lpSock->phy->_verbose)
									printf("Got length %u remaining packet %u\n", length, Len);
								lpSock->part_received = (SocketRawData *)malloc(length + sizeof(SocketRawData));
								lpSock->part_received->Buffer = (uint8_t *)lpSock->part_received+sizeof(SocketRawData);
								lpSock->part_received->Length = length;
								if (length > Len)
									length = Len;

								if (!length)
									break;

								memcpy(lpSock->part_received->Buffer+lpSock->part_offset-sizeof(length), Buf, length);
								lpSock->part_offset += length;
								Len -= length;
								Buf += length;

								if (lpSock->part_offset - sizeof(length) == lpSock->part_received->Length) {
									lpSock->phy->quicOnData(lpSock->s, lpSock->part_received, lpSock, &lpSock->saddr, &lpSock->saddr);
									lpSock->part_received = NULL;
									lpSock->part_offset = 0;
								}
							} else {
								memcpy(lpSock->length_buf+lpSock->part_offset, Buf, Len);
								lpSock->part_offset += Len;
								break;
							}
						}
					} while (Len > 0);

					if (lpSock->phy->_verbose)
						printf("[strm][%p][Sock][%p] Data received %lld size %u\n", Stream, lpSock->s, lpSock->nreceived, qb.Length);

					lpSock->nreceived++;
                }
                
            }
			break;
		case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
			//
			// The peer gracefully shut down its send direction of the stream.
			//
			if (lpSock->phy->_verbose)
				printf("[strm][%p] Peer aborted\n", Stream);
			break;
		case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
			//
			// The peer aborted its send direction of the stream.
			//
			if (lpSock->phy->_verbose)
				printf("[strm][%p] Peer shut down\n", Stream);
			break;
		case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
			//
			// Both directions of the stream have been shut down and MsQuic is done
			// with the stream. It can now be safely cleaned up.
			//
			if (lpSock->phy->_verbose)
				printf("[strm][%p] All done\n", Stream);
			if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
				Phy::quicShutdown(lpSock);
			}
			break;
		default:
			break;
		}
		return QUIC_STATUS_SUCCESS;
	}

	inline static
	void
	WriteSslKeyLogFile(
		_In_z_ const char* FileName,
		_In_ QUIC_TLS_SECRETS& TlsSecrets
		)
	{
		FILE* File = nullptr;
	#ifdef _WIN32
		File = _fsopen(FileName, "ab", _SH_DENYNO);
	#else
		File = fopen(FileName, "ab");
	#endif

		if (File == nullptr) {
			printf("Failed to open sslkeylogfile %s\n", FileName);
			return;
		}
		if (fseek(File, 0, SEEK_END) == 0 && ftell(File) == 0) {
			fprintf(File, "# TLS 1.3 secrets log file, generated by quicinterop\n");
		}
		char ClientRandomBuffer[(2 * sizeof(QUIC_TLS_SECRETS::ClientRandom)) + 1] = {0};
		char TempHexBuffer[(2 * QUIC_TLS_SECRETS_MAX_SECRET_LEN) + 1] = {0};
		if (TlsSecrets.IsSet.ClientRandom) {
			EncodeHexBuffer(
				TlsSecrets.ClientRandom,
				(uint8_t)sizeof(TlsSecrets.ClientRandom),
				ClientRandomBuffer);
		}

		if (TlsSecrets.IsSet.ClientEarlyTrafficSecret) {
			EncodeHexBuffer(
				TlsSecrets.ClientEarlyTrafficSecret,
				TlsSecrets.SecretLength,
				TempHexBuffer);
			fprintf(
				File,
				"CLIENT_EARLY_TRAFFIC_SECRET %s %s\n",
				ClientRandomBuffer,
				TempHexBuffer);
		}

		if (TlsSecrets.IsSet.ClientHandshakeTrafficSecret) {
			EncodeHexBuffer(
				TlsSecrets.ClientHandshakeTrafficSecret,
				TlsSecrets.SecretLength,
				TempHexBuffer);
			fprintf(
				File,
				"CLIENT_HANDSHAKE_TRAFFIC_SECRET %s %s\n",
				ClientRandomBuffer,
				TempHexBuffer);
		}

		if (TlsSecrets.IsSet.ServerHandshakeTrafficSecret) {
			EncodeHexBuffer(
				TlsSecrets.ServerHandshakeTrafficSecret,
				TlsSecrets.SecretLength,
				TempHexBuffer);
			fprintf(
				File,
				"SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s\n",
				ClientRandomBuffer,
				TempHexBuffer);
		}

		if (TlsSecrets.IsSet.ClientTrafficSecret0) {
			EncodeHexBuffer(
				TlsSecrets.ClientTrafficSecret0,
				TlsSecrets.SecretLength,
				TempHexBuffer);
			fprintf(
				File,
				"CLIENT_TRAFFIC_SECRET_0 %s %s\n",
				ClientRandomBuffer,
				TempHexBuffer);
		}

		if (TlsSecrets.IsSet.ServerTrafficSecret0) {
			EncodeHexBuffer(
				TlsSecrets.ServerTrafficSecret0,
				TlsSecrets.SecretLength,
				TempHexBuffer);
			fprintf(
				File,
				"SERVER_TRAFFIC_SECRET_0 %s %s\n",
				ClientRandomBuffer,
				TempHexBuffer);
		}

		fflush(File);
		fclose(File);
	}

	inline void quicExecClientConnectionEvents(QUICSocketImpl *q, void *uptr, QUIC_CONNECTION_EVENT_TYPE event)
	{
		switch (event) {
		case QUIC_CONNECTION_EVENT_CONNECTED:
			{
				if (_verbose)
					printf("[conn][%p] Connected\n", q->connection);

				QUIC_STATUS Status;
#ifdef QUIC_STREAM
    			HQUIC Stream = NULL;
#endif
				uint32_t Size = sizeof(QUIC_SETTINGS);
				QUIC_SETTINGS Settings;
				MsQuic->GetParam(
					q->connection,
					QUIC_PARAM_CONN_SETTINGS,
					&Size,
					&Settings
				);
				if (_verbose)
					printf("Client origin settings tlsmaxbuffer %d - %d size %u\n", Settings.TlsClientMaxSendBuffer, Settings.IsSet.TlsClientMaxSendBuffer, Settings.TlsClientMaxSendBuffer);
				
				Settings.IsSet.TlsClientMaxSendBuffer = TRUE;
				Settings.TlsClientMaxSendBuffer = QUICSendBufferSize; // Set the value you want

				Settings.IsSet.TlsServerMaxSendBuffer = TRUE;
				Settings.TlsServerMaxSendBuffer = QUICSendBufferSize; // Set the value you want

				if (_verbose)
					printf("Client set settings tlsmaxbuffer %d - %d size %u\n", Settings.TlsClientMaxSendBuffer, Settings.IsSet.TlsClientMaxSendBuffer, Settings.TlsClientMaxSendBuffer);

				MsQuic->SetParam(
					q->connection,
					QUIC_PARAM_CONN_SETTINGS,
					sizeof(Settings),
					&Settings
				);
				
				if (q->sslKeyLogFile) {
					Phy::WriteSslKeyLogFile(q->sslKeyLogFile, q->TlsSecrets);
				}
#ifdef QUIC_STREAM
				//
				// Create/allocate a new bidirectional stream. The stream is just allocated
				// and no QUIC stream identifier is assigned until it's started.
				//
				if (QUIC_FAILED(Status = MsQuic->StreamOpen(q->connection, QUIC_STREAM_OPEN_FLAG_NONE, QUICClientStreamCallback, q, &Stream))) {
					fprintf(stderr, "StreamOpen failed, 0x%x!\n", Status);
					MsQuic->ConnectionShutdown(q->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
					break;
				}

				if (_verbose)
					printf("[strm][%p] Starting...\n", Stream);

				//
				// Starts the bidirectional stream. By default, the peer is not notified of
				// the stream being started until data is sent on the stream.
				//
				if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
					fprintf(stderr, "StreamStart failed, 0x%x!\n", Status);
					MsQuic->StreamClose(Stream);
					MsQuic->ConnectionShutdown(q->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
					break;
				}
				
				q->type = ZT_PHY_SOCKET_QUIC_OUT_CONNECTED;
				PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(q->s));
				sws.type = q->type;
				q->stream = Stream;
				bool failed = false;
				q->qmutex.lock();
				while (!q->queue.empty()) {
					SocketRawData *data = q->queue.front();

					if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, data, 1, QUIC_SEND_FLAG_NONE, data))) {
						fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
						failed = true;
						break;

					}
					q->queue.pop();
				}
				q->qmutex.unlock();
				if (failed) {
					fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
					Phy::quicShutdown(q);
				}
#else
				q->type = ZT_PHY_SOCKET_QUIC_OUT_CONNECTED;
				bool failed = false;
				q->qmutex.lock();
				while (!q->queue.empty()) {
					SocketRawData *data = q->queue.front();
					if (_verbose)
						printf("Sending datagram size %u\n", data->Length);
					if (QUIC_FAILED(Status = MsQuic->DatagramSend(q->connection, data, 1, QUIC_SEND_FLAG_NONE, data))) {
						fprintf(stderr, "DatagramSend failed, 0x%x!\n", Status);
						failed = true;
						break;

					}
					q->queue.pop();
				}
				q->qmutex.unlock();
				if (failed) {
					fprintf(stderr, "DatagramSend failed, 0x%x!\n", Status);
					//MsQuic->StreamClose(Stream);
					//MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
					//phy->close((PhySocket *)&sws, false);
					//phy->removeSock(sws);
				}

#endif
			}
			break;
#ifndef QUIC_STREAM
		case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
			{
				if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
					lpSock->maxDatagramSize = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;
					if (phy->_verbose) {
						printf("Datagram send enabled max size %d\n", lpSock->maxDatagramSize);
					}
				}
			}
			break;
		case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
			{
				SocketRawData *data = (SocketRawData *)malloc(Event->DATAGRAM_RECEIVED.Buffer->Length + sizeof(SocketRawData));
				memcpy(data+sizeof(SocketRawData), Event->DATAGRAM_RECEIVED.Buffer->Buffer, Event->DATAGRAM_RECEIVED.Buffer->Length);
				data->Length = Event->DATAGRAM_RECEIVED.Buffer->Length;
				data->Buffer = (uint8_t *)data+sizeof(SocketRawData);
				QUIC_RECEIVED_DATA rdata;
				rdata.data = data;
				memcpy(&rdata.from, &(lpSock->saddr), sizeof(rdata.from));
				memcpy(&rdata.to, &(lpSock->saddr), sizeof(rdata.to));

				phy->_pmutex.lock();
				phy->_pqueue.push(rdata);
				phy->_pmutex.unlock();
				phy->whack();
				lpSock->nreceived++;
			}
			break;
		case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
			if (phy->_verbose)
				printf("QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED\n");
			//if (Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext)
			//	free(Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
			break;
#endif
		case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
			//
			// The connection has been shut down by the transport. Generally, this
			// is the expected way for the connection to shut down with this
			// protocol, since we let idle timeout kill the connection.
			//
			if (_verbose) {
				QUIC_STATUS Status = (QUIC_STATUS)(uintptr_t) uptr;
				if (Status == QUIC_STATUS_CONNECTION_IDLE) {
					printf("[conn][%p] Successfully shut down on idle.\n", q->connection);
				} else {
					printf("[conn][%p] Shut down by transport, 0x%x\n", q->connection, Status);
				}
			}
			break;
		case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
			//
			// The connection was explicitly shut down by the peer.
			//
			if (_verbose) {
				QUIC_UINT62 ErrorCode = (QUIC_UINT62)(uintptr_t)uptr;
				printf("[conn][%p] Shut down by peer, 0x%llu\n", q->connection, (unsigned long long)ErrorCode);
			}
			break;
		case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
			//
			// The connection has completed the shutdown process and is ready to be
			// safely cleaned up.
			//
			if (_verbose)
				printf("[conn][%p] All done\n", q->connection);

			this->close(q->s, false);

			break;
		case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
			//
			// A resumption ticket (also called New Session Ticket or NST) was
			// received from the server.
			//
			if (_verbose) {
				uint32_t ResumptionTicketLength = (uint32_t)(uintptr_t)uptr;
				printf("[conn][%p] Resumption ticket received (%u bytes):\n", q->connection, ResumptionTicketLength);
			}
			//for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
			//	printf("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
			//}
			//printf("\n");
			break;
		default:
			break;
		}
	}

	//
	// The clients's callback for connection events from MsQuic.
	//
	_IRQL_requires_max_(DISPATCH_LEVEL)
	_Function_class_(QUIC_CONNECTION_CALLBACK)

	static
	QUIC_STATUS
	QUIC_API
	QUICClientConnectionCallback(
		_In_ HQUIC Connection,
		_In_opt_ void* Context,
		_Inout_ QUIC_CONNECTION_EVENT* Event
		)
	{
		//UNREFERENCED_PARAMETER(Context);
		QUICSocketImpl *lpSock = (QUICSocketImpl *)Context;
		switch (Event->Type) {
		case QUIC_CONNECTION_EVENT_CONNECTED:
			//
			// The handshake has completed for the connection.
			//
			if (lpSock->phy->_verbose)
				printf("[conn][%p] Connected\n", Connection);
			//ClientSend(Connection);
			{
				QUIC_STATUS Status;
#ifdef QUIC_STREAM
    			HQUIC Stream = NULL;
#endif
				uint32_t Size = sizeof(QUIC_SETTINGS);
				QUIC_SETTINGS Settings;
				MsQuic->GetParam(
					Connection,
					QUIC_PARAM_CONN_SETTINGS,
					&Size,
					&Settings
				);
				if (lpSock->phy->_verbose)
					printf("Client origin settings tlsmaxbuffer %d - %d size %u\n", Settings.TlsClientMaxSendBuffer, Settings.IsSet.TlsClientMaxSendBuffer, Settings.TlsClientMaxSendBuffer);
				
				Settings.IsSet.TlsClientMaxSendBuffer = TRUE;
				Settings.TlsClientMaxSendBuffer = QUICSendBufferSize; // Set the value you want

				Settings.IsSet.TlsServerMaxSendBuffer = TRUE;
				Settings.TlsServerMaxSendBuffer = QUICSendBufferSize; // Set the value you want

				if (lpSock->phy->_verbose)
					printf("Client set settings tlsmaxbuffer %d - %d size %u\n", Settings.TlsClientMaxSendBuffer, Settings.IsSet.TlsClientMaxSendBuffer, Settings.TlsClientMaxSendBuffer);

				MsQuic->SetParam(
					Connection,
					QUIC_PARAM_CONN_SETTINGS,
					sizeof(Settings),
					&Settings
				);
				
				if (lpSock->sslKeyLogFile) {
					Phy::WriteSslKeyLogFile(lpSock->sslKeyLogFile, lpSock->TlsSecrets);
				}
#ifdef QUIC_STREAM
				//
				// Create/allocate a new bidirectional stream. The stream is just allocated
				// and no QUIC stream identifier is assigned until it's started.
				//
				if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, QUICClientStreamCallback, Context, &Stream))) {
					fprintf(stderr, "StreamOpen failed, 0x%x!\n", Status);
					MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
					//phy->close((PhySocket *)&sws, false);
					//phy->removeSock(sws);
					break;
				}

				if (lpSock->phy->_verbose)
					printf("[strm][%p] Starting...\n", Stream);

				//
				// Starts the bidirectional stream. By default, the peer is not notified of
				// the stream being started until data is sent on the stream.
				//
				if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
					fprintf(stderr, "StreamStart failed, 0x%x!\n", Status);
					MsQuic->StreamClose(Stream);
					//lpSock->stream = NULL;
					MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
					//phy->close((PhySocket *)&sws, false);
					//phy->removeSock(sws);
					break;
				}
				
				lpSock->type = ZT_PHY_SOCKET_QUIC_OUT_CONNECTED;
				PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(lpSock->s));
				sws.type = lpSock->type;
				lpSock->stream = Stream;
				//lpSock->phy->_handler->phyOnQuicConnect(Context, 0, true);
				bool failed = false;
				lpSock->qmutex.lock();
				while (!lpSock->queue.empty()) {
					SocketRawData *data = lpSock->queue.front();

					if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, data, 1, QUIC_SEND_FLAG_NONE, data))) {
						fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
						failed = true;
						break;

					}
					lpSock->queue.pop();
				}
				lpSock->qmutex.unlock();
				if (failed) {
					fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
					//MsQuic->StreamClose(Stream);
					//MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
					Phy::quicShutdown(lpSock);
				}
#else
				lpSock->type = ZT_PHY_SOCKET_QUIC_OUT_CONNECTED;
				bool failed = false;
				lpSock->qmutex.lock();
				while (!lpSock->queue.empty()) {
					SocketRawData *data = lpSock->queue.front();
					if (phy->_verbose)
						printf("Sending datagram size %u\n", data->Length);
					if (QUIC_FAILED(Status = MsQuic->DatagramSend(Connection, data, 1, QUIC_SEND_FLAG_NONE, data))) {
						fprintf(stderr, "DatagramSend failed, 0x%x!\n", Status);
						failed = true;
						break;

					}
					lpSock->queue.pop();
				}
				lpSock->qmutex.unlock();
				if (failed) {
					fprintf(stderr, "DatagramSend failed, 0x%x!\n", Status);
					//MsQuic->StreamClose(Stream);
					//MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
					phy->close((PhySocket *)&sws, false);
					phy->removeSock(sws);
				}

#endif
			}
			break;
#ifndef QUIC_STREAM
		case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
			{
				if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
					lpSock->maxDatagramSize = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;
					if (phy->_verbose) {
						printf("Datagram send enabled max size %d\n", lpSock->maxDatagramSize);
					}
				}
			}
			break;
		case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
			{
				SocketRawData *data = (SocketRawData *)malloc(Event->DATAGRAM_RECEIVED.Buffer->Length + sizeof(SocketRawData));
				memcpy(data+sizeof(SocketRawData), Event->DATAGRAM_RECEIVED.Buffer->Buffer, Event->DATAGRAM_RECEIVED.Buffer->Length);
				data->Length = Event->DATAGRAM_RECEIVED.Buffer->Length;
				data->Buffer = (uint8_t *)data+sizeof(SocketRawData);
				QUIC_RECEIVED_DATA rdata;
				rdata.data = data;
				memcpy(&rdata.from, &(lpSock->saddr), sizeof(rdata.from));
				memcpy(&rdata.to, &(lpSock->saddr), sizeof(rdata.to));

				phy->_pmutex.lock();
				phy->_pqueue.push(rdata);
				phy->_pmutex.unlock();
				phy->whack();
				lpSock->nreceived++;
			}
			break;
		case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
			if (phy->_verbose)
				printf("QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED\n");
			//if (Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext)
			//	free(Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
			break;
#endif
		case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
			//
			// The connection has been shut down by the transport. Generally, this
			// is the expected way for the connection to shut down with this
			// protocol, since we let idle timeout kill the connection.
			//
			if (lpSock->phy->_verbose) {
				if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
					printf("[conn][%p] Successfully shut down on idle.\n", Connection);
				} else {
					printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
				}
			}
			break;
		case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
			//
			// The connection was explicitly shut down by the peer.
			//
			if (lpSock->phy->_verbose)
				printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
			break;
		case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
			//
			// The connection has completed the shutdown process and is ready to be
			// safely cleaned up.
			//
			if (lpSock->phy->_verbose)
				printf("[conn][%p] All done\n", Connection);

			if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress)
			{
				QUICEvent *event = new QUICEvent(lpSock, NULL, ZT_QUIC_CLIENT_CONNECTION_EVENT, (int)QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE);
				lpSock->phy->_emutex.lock();
				lpSock->phy->_equeue.push(event);
				lpSock->phy->_emutex.unlock();
				lpSock->phy->whack();
			}
			break;
		case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
			//
			// A resumption ticket (also called New Session Ticket or NST) was
			// received from the server.
			//
			if (lpSock->phy->_verbose)
				printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
			//for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
			//	printf("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
			//}
			//printf("\n");
			break;
		default:
			break;
		}
		return QUIC_STATUS_SUCCESS;
	}

	inline QUICSocketImpl *quicConnect(const struct sockaddr *remoteAddress,bool &connected,void *uptr = (void *)0,bool callConnectHandler = true)
	{
		QUICSocketImpl *lpSock = NULL;
		if (!quicInit())
			return lpSock;

		if (!QUICConfigurationClient) {

			QUIC_SETTINGS Settings;
			memset(&Settings, 0, sizeof(Settings));
			//
			// Configures the client's idle timeout.
			//
			Settings.IdleTimeoutMs = QUICIdleTimeoutMs;
			Settings.IsSet.IdleTimeoutMs = TRUE;
#ifndef QUIC_STREAM
			Settings.DatagramReceiveEnabled = TRUE;
#endif
			//
			// Configures a default client configuration, optionally disabling
			// server certificate validation.
			//
			QUIC_CREDENTIAL_CONFIG CredConfig;
			memset(&CredConfig, 0, sizeof(CredConfig));
			CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
			CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
			//if (Unsecure) {
				CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
			//}

			//
			// Allocate/initialize the configuration object, with the configured ALPN
			// and settings.
			//
			QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
			if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(QUICRegistration, &QUICAlpn, 1, &Settings, sizeof(Settings), NULL, &QUICConfigurationClient))) {
				fprintf(stderr, "ConfigurationOpen failed, 0x%x!\n", Status);
				return lpSock;
			}

			//
			// Loads the TLS credential part of the configuration. This is required even
			// on client side, to indicate if a certificate is required or not.
			//
			if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(QUICConfigurationClient, &CredConfig))) {
				fprintf(stderr, "ConfigurationLoadCredential failed, 0x%x!\n", Status);
				MsQuic->ConfigurationClose(QUICConfigurationClient);
				QUICConfigurationClient = NULL;
				return lpSock;
			}
		}

		QUIC_STATUS Status;
		//const char* ResumptionTicketString = NULL;
		HQUIC Connection = NULL;

		do {

			lpSock = new QUICSocketImpl(this);
			//
			// Allocate a new connection object.
			//
			if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(QUICRegistration, QUICClientConnectionCallback, lpSock, &Connection))) {
				fprintf(stderr, "ConnectionOpen failed, 0x%x!\n", Status);
				break;
			}

			lpSock->connection = Connection;

			/*
			if ((ResumptionTicketString = GetValue(argc, argv, "ticket")) != NULL) {
				//
				// If provided at the command line, set the resumption ticket that can
				// be used to resume a previous session.
				//
				uint8_t ResumptionTicket[10240];
				uint16_t TicketLength = (uint16_t)DecodeHexBuffer(ResumptionTicketString, sizeof(ResumptionTicket), ResumptionTicket);
				if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_RESUMPTION_TICKET, TicketLength, ResumptionTicket))) {
					printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n", Status);
					goto Error;
				}
			}
			*/
			if (sslKeyLogFile) {
				if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_TLS_SECRETS, sizeof(lpSock->TlsSecrets), (uint8_t*)&lpSock->TlsSecrets))) {
					fprintf(stderr, "Couldn't set sslKeyLogFile %s\n", sslKeyLogFile);
				} else {
					lpSock->sslKeyLogFile = sslKeyLogFile;
				}
			}

			//
			// Get the target / server name or IP from the command line.
			//
			char Target[1000];
			int Port;
			if (remoteAddress->sa_family == AF_INET6) {
				struct sockaddr_in6 *addr = (struct  sockaddr_in6 *) remoteAddress;
				socklen_t Tlen = sizeof(Target);
				Port = ntohs(addr->sin6_port);
				inet_ntop(remoteAddress->sa_family, &addr->sin6_addr.__in6_u, Target, Tlen);
			} else {
				struct sockaddr_in *addr = (struct  sockaddr_in *) remoteAddress;
				socklen_t Tlen = sizeof(Target);
				Port = ntohs(addr->sin_port);
				inet_ntop(remoteAddress->sa_family, &addr->sin_addr.s_addr, Target, Tlen);
			}

			if (_verbose)
				printf("[conn][%p] Connecting to %s:%d...\n", Connection, Target, Port);
			//
			// Start the connection to the server.
			//
			if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, QUICConfigurationClient, QUIC_ADDRESS_FAMILY_UNSPEC, Target, Port))) {
				fprintf(stderr, "ConnectionStart failed, 0x%x!\n", Status);
				break;
			}

			
			lpSock->type = ZT_PHY_SOCKET_QUIC_OUT_PENDING;
			memset(&(lpSock->saddr),0,sizeof(lpSock->saddr));
			memcpy(&(lpSock->saddr),remoteAddress,(remoteAddress->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));

			try {

				_socks.push_back(PhySocketImpl());
				PhySocketImpl &sws = _socks.back();
				sws.quic = refQuicSocket(lpSock);
				sws.sock = lpSock->id;
				lpSock->s = (PhySocket *)&sws;
				memcpy(&(sws.saddr), &lpSock->saddr, sizeof(lpSock->saddr));
				sws.type = lpSock->type;

			} catch (...) {

				delete lpSock;

				return (QUICSocketImpl *)0;
			}

			return lpSock;

		} while (0);

		delete lpSock;

		return (QUICSocketImpl *)0;
	}

	inline bool quicSend(int64_t localSocket, const struct sockaddr *remoteAddress,const void *data,unsigned long len)
	{
		uint8_t *idata = (uint8_t *)data;
		if (localSocket != -1 && localSocket != 0) {
			bool found = false;
			PhySocket *psock = (PhySocket *)((uintptr_t)localSocket);
			PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(psock));
			for(typename std::list<PhySocketImpl>::iterator s(_socks.begin());s!=_socks.end();++s) {
				PhySocketImpl &sws2 = *s;
				PhySocket *psock2 = (PhySocket *)&sws2;
				if (psock == psock2) {
					found = true;
					break;
				}
			}
			if (found && sws.type != ZT_PHY_SOCKET_QUIC_SHUTTINGDOWN && sws.type != ZT_PHY_SOCKET_CLOSED && sws.quic) {
				if (sws.quic->stream) {
					QUIC_STATUS Status;
					bool failed = false;

					if (_verbose)
						printf("[strm][%p][Sock][%p] Sending data size %u\n", sws.quic->stream, sws.quic->s, len);
					
					sws.quic->qmutex.lock();
					while (!sws.quic->queue.empty()) {
						SocketRawData *data = sws.quic->queue.front();
	#ifdef QUIC_STREAM
						if (QUIC_FAILED(Status = MsQuic->StreamSend(sws.quic->stream, data, 1, QUIC_SEND_FLAG_NONE, data))) {
							fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
							failed = true;
							break;

						}
	#else
						if (_verbose)
							printf("Sending datagram size %u\n", data->Length);
						if (QUIC_FAILED(Status = MsQuic->DatagramSend(sws.quic->connection, data, 1, QUIC_SEND_FLAG_NONE, data))) {
							fprintf(stderr, "DatagramSend failed, 0x%x!\n", Status);
							failed = true;
							break;

						}
	#endif
						sws.quic->queue.pop();
					}
					sws.quic->qmutex.unlock();
					if (!failed) {
						unsigned int ilen = (unsigned int)len;
						unsigned int segLen = ilen > QUICSendBufferSize - sizeof(ilen) ? QUICSendBufferSize - sizeof(ilen) : ilen;
						SocketRawData *rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+segLen+sizeof(ilen));
						rawData->Length = segLen+sizeof(ilen);
						rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
						memcpy(rawData->Buffer, &ilen, sizeof(ilen));
						memcpy(rawData->Buffer+sizeof(ilen), idata, segLen);

	#ifdef QUIC_STREAM
						if (QUIC_FAILED(Status = MsQuic->StreamSend(sws.quic->stream, rawData, 1, QUIC_SEND_FLAG_NONE, rawData))) {
							fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
							failed = true;
						}

						ilen -= segLen;
						idata += segLen;
						while (!failed && ilen > 0) {
							segLen = ilen > QUICSendBufferSize ? QUICSendBufferSize : ilen;
							rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+segLen);
							rawData->Length = segLen;
							rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
							memcpy(rawData->Buffer, idata, segLen);
							ilen -= segLen;
							idata += segLen;

							if (QUIC_FAILED(Status = MsQuic->StreamSend(sws.quic->stream, rawData, 1, QUIC_SEND_FLAG_NONE, rawData))) {
								fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
								failed = true;
							}
						}
	#else
						if (_verbose)
							printf("Sending datagram size %u\n", rawData->Length);
						if (QUIC_FAILED(Status = MsQuic->DatagramSend(sws.quic->connection, rawData, 1, QUIC_SEND_FLAG_NONE, rawData))) {
							fprintf(stderr, "DatagramSend failed, 0x%x!\n", Status);
							failed = true;
							break;

						}
	#endif
					}
					if (failed) {
						fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
						Phy::quicShutdown(sws.quic);
						return false;
					}
				} else {
					unsigned int ilen = (unsigned int)len;
					unsigned int segLen = ilen > QUICSendBufferSize - sizeof(ilen) ? QUICSendBufferSize - sizeof(ilen) : ilen;
					SocketRawData *rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+segLen+sizeof(ilen));
					rawData->Length = segLen+sizeof(ilen);
					rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
					memcpy(rawData->Buffer, &ilen, sizeof(ilen));
					memcpy(rawData->Buffer+sizeof(ilen), idata, segLen);
					sws.quic->qmutex.lock();
					sws.quic->queue.push(rawData);
					sws.quic->qmutex.unlock();

					ilen -= segLen;
					idata += segLen;
					while (ilen > 0) {
						segLen = ilen > QUICSendBufferSize ? QUICSendBufferSize : ilen;
						rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+segLen);
						rawData->Length = segLen;
						rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
						memcpy(rawData->Buffer, idata, segLen);
						sws.quic->qmutex.lock();
						sws.quic->queue.push(rawData);
						sws.quic->qmutex.unlock();
						ilen -= segLen;
						idata += segLen;
					}
				}

				Metrics::udp_send += len;

				return true;
			}
		}

		for(typename std::list<PhySocketImpl>::iterator s(_socks.begin());s!=_socks.end();++s) {
			if (s->type < ZT_PHY_SOCKET_QUIC_OUT_PENDING || s->type > ZT_PHY_SOCKET_QUIC_IN)
				continue;
			const struct sockaddr *remoteAddress2 = (struct sockaddr *)&s->saddr;
			if (remoteAddress2->sa_family == remoteAddress->sa_family) {
				struct sockaddr_in *addr4_in1 = (struct sockaddr_in *)remoteAddress;
				struct sockaddr_in *addr4_in2 = (struct sockaddr_in *)remoteAddress2;
				struct sockaddr_in6 *addr6_in1 = (struct sockaddr_in6 *)remoteAddress;
				struct sockaddr_in6 *addr6_in2 = (struct sockaddr_in6 *)remoteAddress2;
				void *nul = NULL;

				if (_verbose) {
					printf("remote addr %x port %d - local addr %x port %d quic %p stream %p sock %p\n", addr4_in1->sin_addr.s_addr, htons(addr4_in1->sin_port), addr4_in2->sin_addr.s_addr, htons(addr4_in2->sin_port), s->quic, s->quic? s->quic->stream : nul, s->quic? s->quic->s : nul);
				}

				if ((remoteAddress->sa_family == AF_INET && addr4_in1->sin_addr.s_addr == addr4_in2->sin_addr.s_addr && addr4_in1->sin_port == addr4_in2->sin_port)
				||(remoteAddress->sa_family == AF_INET6 && memcmp(&addr6_in1->sin6_addr, &addr6_in2->sin6_addr, sizeof(addr6_in2->sin6_addr)) == 0 
				&& addr6_in1->sin6_port == addr6_in2->sin6_port)) 
				{
					QUIC_STATUS Status;
#ifdef QUIC_STREAM
					if (s->quic && s->quic->stream) {
#else
					if (s->quic && s->quic->connection && s->quic->maxDatagramSize) {
#endif
						bool failed = false;

						if (_verbose)
							printf("[strm][%p][Sock][%p] Sending data size %u\n", s->quic->stream, s->quic->s, len);
						
						s->quic->qmutex.lock();
						while (!s->quic->queue.empty()) {
							SocketRawData *data = s->quic->queue.front();
#ifdef QUIC_STREAM
							if (QUIC_FAILED(Status = MsQuic->StreamSend(s->quic->stream, data, 1, QUIC_SEND_FLAG_NONE, data))) {
								fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
								failed = true;
								break;

							}
#else
							if (_verbose)
								printf("Sending datagram size %u\n", data->Length);
							if (QUIC_FAILED(Status = MsQuic->DatagramSend((HQUIC)s->quic->connection, data, 1, QUIC_SEND_FLAG_NONE, data))) {
								fprintf(stderr, "DatagramSend failed, 0x%x!\n", Status);
								failed = true;
								break;

							}
#endif
							s->quic->queue.pop();
						}
						s->quic->qmutex.unlock();
						if (!failed) {
							unsigned int ilen = (unsigned int)len;
							unsigned int segLen = ilen > QUICSendBufferSize - sizeof(ilen) ? QUICSendBufferSize - sizeof(ilen) : ilen;
							SocketRawData *rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+segLen+sizeof(ilen));
							rawData->Length = segLen+sizeof(ilen);
							rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
							memcpy(rawData->Buffer, &ilen, sizeof(ilen));
							memcpy(rawData->Buffer+sizeof(ilen), idata, segLen);
#ifdef QUIC_STREAM
							if (QUIC_FAILED(Status = MsQuic->StreamSend(s->quic->stream, rawData, 1, QUIC_SEND_FLAG_NONE, rawData))) {
								fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
								failed = true;
							}

							ilen -= segLen;
							idata += segLen;
							while (!failed && ilen > 0) {
								segLen = ilen > QUICSendBufferSize ? QUICSendBufferSize : ilen;
								rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+segLen);
								rawData->Length = segLen;
								rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
								memcpy(rawData->Buffer, idata, segLen);
								ilen -= segLen;
								idata += segLen;

								if (QUIC_FAILED(Status = MsQuic->StreamSend(s->quic->stream, rawData, 1, QUIC_SEND_FLAG_NONE, rawData))) {
									fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
									failed = true;
								}
							}
#else
							if (_verbose)
								printf("Sending datagram size %u\n", rawData->Length);
							if (QUIC_FAILED(Status = MsQuic->DatagramSend((HQUIC)s->quic->connection, rawData, 1, QUIC_SEND_FLAG_NONE, rawData))) {
								fprintf(stderr, "DatagramSend failed, 0x%x!\n", Status);
								failed = true;
								break;

							}
#endif
						}
						if (failed) {
							fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
							Phy::quicShutdown(s->quic);
							return false;
						}
						
						Metrics::udp_send += len;

						return true;

					} else if (s->quic) {
						unsigned int ilen = (unsigned int)len;
						unsigned int segLen = ilen > QUICSendBufferSize - sizeof(ilen) ? QUICSendBufferSize - sizeof(ilen) : ilen;
						SocketRawData *rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+segLen+sizeof(ilen));
						rawData->Length = segLen+sizeof(ilen);
						rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
						memcpy(rawData->Buffer, &ilen, sizeof(ilen));
						memcpy(rawData->Buffer+sizeof(ilen), idata, segLen);
						s->quic->qmutex.lock();
						s->quic->queue.push(rawData);
						s->quic->qmutex.unlock();

						ilen -= segLen;
						idata += segLen;
						while (ilen > 0) {
							segLen = ilen > QUICSendBufferSize ? QUICSendBufferSize : ilen;
							rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+segLen);
							rawData->Length = segLen;
							rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
							memcpy(rawData->Buffer, idata, segLen);
							s->quic->qmutex.lock();
							s->quic->queue.push(rawData);
							s->quic->qmutex.unlock();
							ilen -= segLen;
							idata += segLen;
						}

						Metrics::udp_send += len;

						return true;
					}
				}
			}
		}

		bool connected = false;
		QUICSocketImpl *lpSock = quicConnect(remoteAddress, connected);
		if (!lpSock)
			return false;

		//send source port at the beginning of stream
		SocketRawData *rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+sizeof(_primaryPort));
		rawData->Length = sizeof(_primaryPort);
		rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
		memcpy(rawData->Buffer, &_primaryPort, sizeof(_primaryPort));
		lpSock->qmutex.lock();
		lpSock->queue.push(rawData);
		lpSock->qmutex.unlock();

		unsigned int ilen = (unsigned int)len;
		unsigned int segLen = ilen > QUICSendBufferSize - sizeof(ilen) ? QUICSendBufferSize - sizeof(ilen) : ilen;
		rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+segLen+sizeof(ilen));
		rawData->Length = segLen+sizeof(ilen);
		rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
		memcpy(rawData->Buffer, &ilen, sizeof(ilen));
		memcpy(rawData->Buffer+sizeof(ilen), idata, segLen);
		lpSock->qmutex.lock();
		lpSock->queue.push(rawData);
		lpSock->qmutex.unlock();

		ilen -= segLen;
		idata += segLen;
		while (ilen > 0) {
			segLen = ilen > QUICSendBufferSize ? QUICSendBufferSize : ilen;
			rawData = (SocketRawData *)malloc(sizeof(SocketRawData)+segLen);
			rawData->Length = segLen;
			rawData->Buffer = (uint8_t *)rawData+sizeof(SocketRawData);
			memcpy(rawData->Buffer, idata, segLen);
			lpSock->qmutex.lock();
			lpSock->queue.push(rawData);
			lpSock->qmutex.unlock();
			ilen -= segLen;
			idata += segLen;
		}

		Metrics::udp_send += len;

		return true;
	}

	inline void quicExecServerStreamEvents(QUICSocketImpl *q, void *uptr, QUIC_STREAM_EVENT_TYPE event)
	{
		switch (event) {
		case QUIC_STREAM_EVENT_SEND_COMPLETE:
			//
			// A previous StreamSend call has completed, and the context is being
			// returned back to the app.
			//
			free(uptr);
			//if (phy->_verbose)
			//	printf("[strm][%p] Data sent\n", Stream);
			break;
		case QUIC_STREAM_EVENT_RECEIVE:
			break;
		case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
			//
			// The peer gracefully shut down its send direction of the stream.
			//
			if (_verbose)
				printf("[strm][%p] Peer shut down\n", q->stream);
			//ServerSend(Stream);
			break;
		case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
			//
			// The peer aborted its send direction of the stream.
			//
			if (_verbose)
				printf("[strm][%p] Peer aborted\n", q->stream);
			MsQuic->StreamShutdown(q->stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
			break;
		case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
			//
			// Both directions of the stream have been shut down and MsQuic is done
			// with the stream. It can now be safely cleaned up.
			//
			if (_verbose)
				printf("[strm][%p] All done\n", q->stream);
			Phy::quicShutdown(q);
			break;
		default:
			break;
		}
	}

	//
	// The server's callback for stream events from MsQuic.
	//
	_IRQL_requires_max_(DISPATCH_LEVEL)
	_Function_class_(QUIC_STREAM_CALLBACK)

	static
	QUIC_STATUS
	QUIC_API
	QUICServerStreamCallback(
		_In_ HQUIC Stream,
		_In_opt_ void* Context,
		_Inout_ QUIC_STREAM_EVENT* Event
		)
	{
		//UNREFERENCED_PARAMETER(Context);
		QUICSocketImpl *lpSock = (QUICSocketImpl *)Context;
		switch (Event->Type) {
		case QUIC_STREAM_EVENT_SEND_COMPLETE:
			//
			// A previous StreamSend call has completed, and the context is being
			// returned back to the app.
			//
			free(Event->SEND_COMPLETE.ClientContext);
			//if (phy->_verbose)
			//	printf("[strm][%p] Data sent\n", Stream);
			break;
		case QUIC_STREAM_EVENT_RECEIVE:
			//
			// Data was received from the peer on the stream.
			//
			//if (phy->_verbose)
				//printf("[strm][%p] Data received\n", Stream);
			{
                uint32_t i;
                for (i=0; i<Event->RECEIVE.BufferCount; i++) {
                    QUIC_BUFFER qb = Event->RECEIVE.Buffers[i];
					unsigned int Len = qb.Length;
					uint8_t *Buf = qb.Buffer;
					do {
						if (lpSock->part_received) {
							unsigned int length = Len;
							unsigned int rem = lpSock->part_received->Length - (lpSock->part_offset - sizeof(length));

							if (length > rem) {
								length = rem;
							}
							
							if (lpSock->phy->_verbose)
								printf("Pkt len = %u current = %u. Need length %u - rem %u to complete remaining packet %u\n", lpSock->part_received->Length, lpSock->part_offset - sizeof(length), length, rem, Len);

							memcpy(lpSock->part_received->Buffer+lpSock->part_offset-sizeof(length), Buf, length);
							lpSock->part_offset += length;
							Len -= length;
							Buf += length;

							if (lpSock->part_offset - sizeof(length) == lpSock->part_received->Length) {
								lpSock->phy->quicOnData(lpSock->s, lpSock->part_received, lpSock, &lpSock->saddr, &lpSock->saddr);
								lpSock->part_received = NULL;
								lpSock->part_offset = 0;
							}

						} else {
							unsigned int length = 0;
							if (lpSock->nreceived == 0) {
								int port;
								PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(lpSock->s));
								struct sockaddr *addr = (struct sockaddr *)&lpSock->saddr;
								struct sockaddr *saddr = (struct sockaddr *)&(sws.saddr);
								memcpy(&port, Buf, sizeof(port));
								if (addr->sa_family == AF_INET6) {
									struct sockaddr_in6 *a61 = (struct sockaddr_in6 *)addr;
									a61->sin6_port = htons(port);
									a61 = (struct sockaddr_in6 *)saddr;
									a61->sin6_port = htons(port);
								} else {
									struct sockaddr_in *a41 = (struct sockaddr_in *)addr;
									a41->sin_port = htons(port);
									a41 = (struct sockaddr_in *)saddr;
									a41->sin_port = htons(port);
								}
								if (lpSock->phy->_verbose)
									printf("[strm][%p][Sock][%p] update port to %d\n", Stream, lpSock->s, port);

								Len -= sizeof(port);
								Buf += sizeof(port);
								lpSock->nreceived++;
							}
							if (lpSock->part_offset + Len >= sizeof(length)) {
								if (lpSock->part_offset < sizeof(length)) {
									unsigned int rem = sizeof(length) - lpSock->part_offset;
									memcpy(lpSock->length_buf+lpSock->part_offset, Buf, rem);
									memcpy(&length, lpSock->length_buf, sizeof(length));
									lpSock->part_offset += rem;
									Len -= rem;
									Buf += rem;
								}
								if (lpSock->phy->_verbose)
									printf("Got length %u remaining packet %u\n", length, Len);
								lpSock->part_received = (SocketRawData *)malloc(length + sizeof(SocketRawData));
								lpSock->part_received->Buffer = (uint8_t *)lpSock->part_received+sizeof(SocketRawData);
								lpSock->part_received->Length = length;
								if (length > Len)
									length = Len;

								if (!length)
									break;

								memcpy(lpSock->part_received->Buffer+lpSock->part_offset-sizeof(length), Buf, length);
								lpSock->part_offset += length;
								Len -= length;
								Buf += length;

								if (lpSock->part_offset - sizeof(length) == lpSock->part_received->Length) {
									lpSock->phy->quicOnData(lpSock->s, lpSock->part_received, lpSock, &lpSock->saddr, &lpSock->saddr);
									lpSock->part_received = NULL;
									lpSock->part_offset = 0;
								}
							} else {
								memcpy(lpSock->length_buf+lpSock->part_offset, Buf, Len);
								lpSock->part_offset += Len;
								break;
							}
						}
					} while (Len > 0);

					if (lpSock->phy->_verbose)
						printf("[strm][%p][Sock][%p] Data received %lld size %u\n", Stream, lpSock->s, lpSock->nreceived, qb.Length);

					lpSock->nreceived++;
                }
                
            }
			break;
		case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
			//
			// The peer gracefully shut down its send direction of the stream.
			//
			if (lpSock->phy->_verbose)
				printf("[strm][%p] Peer shut down\n", Stream);
			break;
		case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
			//
			// The peer aborted its send direction of the stream.
			//
			if (lpSock->phy->_verbose)
				printf("[strm][%p] Peer aborted\n", Stream);
			MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
			break;
		case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
			//
			// Both directions of the stream have been shut down and MsQuic is done
			// with the stream. It can now be safely cleaned up.
			//
			if (lpSock->phy->_verbose)
				printf("[strm][%p] All done\n", Stream);
			Phy::quicShutdown(lpSock);
			break;
		default:
			break;
		}
		return QUIC_STATUS_SUCCESS;
	}

	inline void quicExecServerConnectionEvents(QUICSocketImpl *q, void *uptr, QUIC_CONNECTION_EVENT_TYPE event)
	{
		switch (event)
		{
		case QUIC_CONNECTION_EVENT_CONNECTED:
			//
			// The handshake has completed for the connection.
			//
			{
				uint32_t Size = sizeof(QUIC_SETTINGS);
				QUIC_SETTINGS Settings;
				MsQuic->GetParam(
					q->connection,
					QUIC_PARAM_CONN_SETTINGS,
					&Size,
					&Settings
				);
				if (_verbose)
					printf("Client origin settings tlsmaxbuffer %d - %d size %u\n", Settings.TlsClientMaxSendBuffer, Settings.IsSet.TlsClientMaxSendBuffer, Settings.TlsClientMaxSendBuffer);

				Settings.IsSet.TlsClientMaxSendBuffer = TRUE;
				Settings.TlsClientMaxSendBuffer = QUICSendBufferSize; // Set the value you want

				Settings.IsSet.TlsServerMaxSendBuffer = TRUE;
				Settings.TlsServerMaxSendBuffer = QUICSendBufferSize; // Set the value you want

				if (_verbose)
					printf("Client set settings tlsmaxbuffer %d - %d size %u\n", Settings.TlsClientMaxSendBuffer, Settings.IsSet.TlsClientMaxSendBuffer, Settings.TlsClientMaxSendBuffer);

				MsQuic->SetParam(
					q->connection,
					QUIC_PARAM_CONN_SETTINGS,
					sizeof(Settings),
					&Settings
				);
			}
			
			if (_verbose)
				printf("Client [conn][%p] Connected\n", q->connection);
			MsQuic->ConnectionSendResumptionTicket(q->connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
			break;
#ifndef QUIC_STREAM
		case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
			{
				if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
					lpSock->maxDatagramSize = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;
					if (phy->_verbose) {
						printf("Datagram send enabled max size %d\n", lpSock->maxDatagramSize);
					}
				}
			}
			break;
		case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
			{
				if (lpSock->nreceived == 0) {
					/*
					ZT_PHY_SOCKADDR_STORAGE_TYPE saddr;
					struct sockaddr *addr = (struct sockaddr *)&lpSock->saddr;
					memcpy(&saddr, qb.Buffer, sizeof(saddr));
					*/
					int port;
					struct sockaddr *addr = (struct sockaddr *)&lpSock->saddr;
					memcpy(&port, Event->DATAGRAM_RECEIVED.Buffer->Buffer, sizeof(phy->_primaryPort));
					//update the port
					if (addr->sa_family == AF_INET6) {
						struct sockaddr_in6 *a61 = (struct sockaddr_in6 *)addr;
						//struct sockaddr_in6 *a62 = (struct sockaddr_in6 *)&saddr;
						a61->sin6_port = htons(port);
					} else {
						struct sockaddr_in *a41 = (struct sockaddr_in *)addr;
						//struct sockaddr_in *a42 = (struct sockaddr_in *)&saddr;
						a41->sin_port = htons(port);
					}
				} else {
					SocketRawData *data = (SocketRawData *)malloc(Event->DATAGRAM_RECEIVED.Buffer->Length + sizeof(SocketRawData));
					memcpy(data+sizeof(SocketRawData), Event->DATAGRAM_RECEIVED.Buffer->Buffer, Event->DATAGRAM_RECEIVED.Buffer->Length);
					data->Length = Event->DATAGRAM_RECEIVED.Buffer->Length;
					data->Buffer = (uint8_t *)data+sizeof(SocketRawData);
					QUIC_RECEIVED_DATA rdata;
					rdata.data = data;
					memcpy(&rdata.from, &(lpSock->saddr), sizeof(rdata.from));
					memcpy(&rdata.to, &(lpSock->saddr), sizeof(rdata.to));

					phy->_pmutex.lock();
					phy->_pqueue.push(rdata);
					phy->_pmutex.unlock();
					phy->whack();
				}
				lpSock->nreceived++;
			}
			break;
		case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
			if (phy->_verbose)
				printf("QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED\n");
			//if (Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext)
			//	free(Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
			break;
#endif
		case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
			//
			// The connection has been shut down by the transport. Generally, this
			// is the expected way for the connection to shut down with this
			// protocol, since we let idle timeout kill the connection.
			//
			if (_verbose) {
				QUIC_STATUS Status = (QUIC_STATUS)(uintptr_t)uptr;
				if (Status == QUIC_STATUS_CONNECTION_IDLE) {
					printf("[conn][%p] Successfully shut down on idle.\n", q->connection);
				} else {
					printf("[conn][%p] Shut down by transport, 0x%x\n", q->connection, Status);
				}
			}
			break;
		case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
			//
			// The connection was explicitly shut down by the peer.
			//
			if (_verbose) {
				QUIC_UINT62 ErrorCode = (QUIC_UINT62)(uintptr_t)uptr;
				printf("[conn][%p] Shut down by peer, 0x%llu\n", q->connection, (unsigned long long)ErrorCode);
			}
			break;
		case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
			//
			// The connection has completed the shutdown process and is ready to be
			// safely cleaned up.
			//
			if (_verbose)
				printf("[conn][%p] All done\n", q->connection);
			
			this->close(q->s, false);
			break;
		case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
			//
			// The peer has started/created a new stream. The app MUST set the
			// callback handler before returning.
			//
			if (q->sslKeyLogFile) {
				Phy::WriteSslKeyLogFile(q->sslKeyLogFile, q->TlsSecrets);
			}
			{
				if (_verbose)
					printf("[strm][%p] Peer started\n", q->stream);
				MsQuic->SetCallbackHandler(q->stream, (void*)QUICServerStreamCallback, q);
				bool failed = false;
				QUIC_STATUS Status;
				q->qmutex.lock();
				while (!q->queue.empty()) {
					SocketRawData *data = q->queue.front();

					if (QUIC_FAILED(Status = MsQuic->StreamSend(q->stream, data, 1, QUIC_SEND_FLAG_NONE, data))) {
						fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
						failed = true;
						break;

					}
					q->queue.pop();
				}
				q->qmutex.unlock();
				if (failed) {
					fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
					Phy::quicShutdown(q);
				}
			}
			break;
		case QUIC_CONNECTION_EVENT_RESUMED:
			//
			// The connection succeeded in doing a TLS resumption of a previous
			// connection's session.
			//
			if (_verbose)
				printf("[conn][%p] Connection resumed!\n", q->connection);
			break;
		default:
			break;
		}
	}

	//
	// The server's callback for connection events from MsQuic.
	//
	_IRQL_requires_max_(DISPATCH_LEVEL)
	_Function_class_(QUIC_CONNECTION_CALLBACK)

	static
	QUIC_STATUS
	QUIC_API
	QUICServerConnectionCallback(
		_In_ HQUIC Connection,
		_In_opt_ void* Context,
		_Inout_ QUIC_CONNECTION_EVENT* Event
		)
	{
		//UNREFERENCED_PARAMETER(Context);
		QUICSocketImpl *lpSock = (QUICSocketImpl *)Context;
		switch (Event->Type) {
		case QUIC_CONNECTION_EVENT_CONNECTED:
			//
			// The handshake has completed for the connection.
			//
			{
				uint32_t Size = sizeof(QUIC_SETTINGS);
				QUIC_SETTINGS Settings;
				MsQuic->GetParam(
					Connection,
					QUIC_PARAM_CONN_SETTINGS,
					&Size,
					&Settings
				);
				if (lpSock->phy->_verbose)
					printf("Client origin settings tlsmaxbuffer %d - %d size %u\n", Settings.TlsClientMaxSendBuffer, Settings.IsSet.TlsClientMaxSendBuffer, Settings.TlsClientMaxSendBuffer);

				Settings.IsSet.TlsClientMaxSendBuffer = TRUE;
				Settings.TlsClientMaxSendBuffer = QUICSendBufferSize; // Set the value you want

				Settings.IsSet.TlsServerMaxSendBuffer = TRUE;
				Settings.TlsServerMaxSendBuffer = QUICSendBufferSize; // Set the value you want

				if (lpSock->phy->_verbose)
					printf("Client set settings tlsmaxbuffer %d - %d size %u\n", Settings.TlsClientMaxSendBuffer, Settings.IsSet.TlsClientMaxSendBuffer, Settings.TlsClientMaxSendBuffer);

				MsQuic->SetParam(
					Connection,
					QUIC_PARAM_CONN_SETTINGS,
					sizeof(Settings),
					&Settings
				);
			}
			
			if (lpSock->phy->_verbose)
				printf("Client [conn][%p] Connected\n", Connection);
			MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
			break;
#ifndef QUIC_STREAM
		case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
			{
				if (Event->DATAGRAM_STATE_CHANGED.SendEnabled) {
					lpSock->maxDatagramSize = Event->DATAGRAM_STATE_CHANGED.MaxSendLength;
					if (phy->_verbose) {
						printf("Datagram send enabled max size %d\n", lpSock->maxDatagramSize);
					}
				}
			}
			break;
		case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
			{
				if (lpSock->nreceived == 0) {
					/*
					ZT_PHY_SOCKADDR_STORAGE_TYPE saddr;
					struct sockaddr *addr = (struct sockaddr *)&lpSock->saddr;
					memcpy(&saddr, qb.Buffer, sizeof(saddr));
					*/
					int port;
					struct sockaddr *addr = (struct sockaddr *)&lpSock->saddr;
					memcpy(&port, Event->DATAGRAM_RECEIVED.Buffer->Buffer, sizeof(phy->_primaryPort));
					//update the port
					if (addr->sa_family == AF_INET6) {
						struct sockaddr_in6 *a61 = (struct sockaddr_in6 *)addr;
						//struct sockaddr_in6 *a62 = (struct sockaddr_in6 *)&saddr;
						a61->sin6_port = htons(port);
					} else {
						struct sockaddr_in *a41 = (struct sockaddr_in *)addr;
						//struct sockaddr_in *a42 = (struct sockaddr_in *)&saddr;
						a41->sin_port = htons(port);
					}
				} else {
					SocketRawData *data = (SocketRawData *)malloc(Event->DATAGRAM_RECEIVED.Buffer->Length + sizeof(SocketRawData));
					memcpy(data+sizeof(SocketRawData), Event->DATAGRAM_RECEIVED.Buffer->Buffer, Event->DATAGRAM_RECEIVED.Buffer->Length);
					data->Length = Event->DATAGRAM_RECEIVED.Buffer->Length;
					data->Buffer = (uint8_t *)data+sizeof(SocketRawData);
					QUIC_RECEIVED_DATA rdata;
					rdata.data = data;
					memcpy(&rdata.from, &(lpSock->saddr), sizeof(rdata.from));
					memcpy(&rdata.to, &(lpSock->saddr), sizeof(rdata.to));

					phy->_pmutex.lock();
					phy->_pqueue.push(rdata);
					phy->_pmutex.unlock();
					phy->whack();
				}
				lpSock->nreceived++;
			}
			break;
		case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
			if (phy->_verbose)
				printf("QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED\n");
			//if (Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext)
			//	free(Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
			break;
#endif
		case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
			//
			// The connection has been shut down by the transport. Generally, this
			// is the expected way for the connection to shut down with this
			// protocol, since we let idle timeout kill the connection.
			//
			if (lpSock->phy->_verbose) {
				if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
					printf("[conn][%p] Successfully shut down on idle.\n", Connection);
				} else {
					printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
				}
			}
			break;
		case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
			//
			// The connection was explicitly shut down by the peer.
			//
			if (lpSock->phy->_verbose)
				printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
			break;
		case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
			//
			// The connection has completed the shutdown process and is ready to be
			// safely cleaned up.
			//
			{
				QUICEvent *event = new QUICEvent(lpSock, NULL, ZT_QUIC_SERVER_CONNECTION_EVENT, (int)QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE);
				lpSock->phy->_emutex.lock();
				lpSock->phy->_equeue.push(event);
				lpSock->phy->_emutex.unlock();
				lpSock->phy->whack();
			}
			break;
		case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
			//
			// The peer has started/created a new stream. The app MUST set the
			// callback handler before returning.
			//
			if (lpSock->sslKeyLogFile) {
				Phy::WriteSslKeyLogFile(lpSock->sslKeyLogFile, lpSock->TlsSecrets);
			}
			{
				if (lpSock->phy->_verbose)
					printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
				MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)QUICServerStreamCallback, Context);
				lpSock->stream = Event->PEER_STREAM_STARTED.Stream;
				bool failed = false;
				QUIC_STATUS Status;
				lpSock->qmutex.lock();
				while (!lpSock->queue.empty()) {
					SocketRawData *data = lpSock->queue.front();

					if (QUIC_FAILED(Status = MsQuic->StreamSend(Event->PEER_STREAM_STARTED.Stream, data, 1, QUIC_SEND_FLAG_NONE, data))) {
						fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
						failed = true;
						break;

					}
					lpSock->queue.pop();
				}
				lpSock->qmutex.unlock();
				if (failed) {
					fprintf(stderr, "StreamSend failed, 0x%x!\n", Status);
					Phy::quicShutdown(lpSock);
				}
			}
			break;
		case QUIC_CONNECTION_EVENT_RESUMED:
			//
			// The connection succeeded in doing a TLS resumption of a previous
			// connection's session.
			//
			if (lpSock->phy->_verbose)
				printf("[conn][%p] Connection resumed!\n", Connection);
			break;
		default:
			break;
		}
		return QUIC_STATUS_SUCCESS;
	}

	inline void quicExecServerListenerEvents(QUICSocketImpl *q, void *uptr, QUIC_LISTENER_EVENT_TYPE event)
	{
		switch (event) {
		case QUIC_LISTENER_EVENT_NEW_CONNECTION:
			{
				try {
					_socks.push_back(PhySocketImpl());
				} catch (...) {
					break;
				}
				PhySocketImpl &sws = _socks.back();
				
				memcpy(&(sws.saddr), &q->saddr, sizeof(q->saddr));
				q->s = (PhySocket *)&sws;
				sws.quic = refQuicSocket(q);
				sws.sock = q->id;
				sws.type = ZT_PHY_SOCKET_QUIC_IN;
				q->type = ZT_PHY_SOCKET_QUIC_IN;
				if (_verbose) {
					int port;
					char address[1000];
					struct sockaddr *addr = (struct sockaddr *)&q->saddr;
					//update the port
					if (addr->sa_family == AF_INET6) {
						struct sockaddr_in6 *a61 = (struct sockaddr_in6 *)addr;
						socklen_t Hlen = sizeof(address);
						port = ntohs(a61->sin6_port);
						inet_ntop(a61->sin6_family, &a61->sin6_addr.__in6_u, address, Hlen);
					} else {
						struct sockaddr_in *a41 = (struct sockaddr_in *)addr;
						socklen_t Hlen = sizeof(address);
						port = ntohs(a41->sin_port);
						inet_ntop(a41->sin_family, &a41->sin_addr.s_addr, address, Hlen);
					}

					printf("Incoming connection %p [Sock][%p] from %s:%d\n", q->connection, q->s, address, port);
				}

#ifndef QUIC_STREAM
				BOOLEAN EnableDatagrams = TRUE;
				MsQuic->SetParam(
					Event->NEW_CONNECTION.Connection,
					QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
					sizeof(EnableDatagrams),
					&EnableDatagrams);
#endif
				//MsQuic->SetCallbackHandler(q->connection, (void*)QUICServerConnectionCallback, (void *)q);
				//Status = MsQuic->ConnectionSetConfiguration(q->connection, QUICConfigurationServer);
			}
			break;
		default:
			break;
		}
	}
	//
	// The server's callback for listener events from MsQuic.
	//
	_IRQL_requires_max_(PASSIVE_LEVEL)
	_Function_class_(QUIC_LISTENER_CALLBACK)

	static
	QUIC_STATUS
	QUIC_API
	QUICServerListenerCallback(
		_In_ HQUIC Listener,
		_In_opt_ void* Context,
		_Inout_ QUIC_LISTENER_EVENT* Event
		)
	{
		UNREFERENCED_PARAMETER(Listener);
		//UNREFERENCED_PARAMETER(Context);
		QUICSocketImpl *lpSock = (QUICSocketImpl *)Context;
		QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
		switch (Event->Type) {
		case QUIC_LISTENER_EVENT_NEW_CONNECTION:
			//
			// A new connection is being attempted by a client. For the handshake to
			// proceed, the server must provide a configuration for QUIC to use. The
			// app MUST set the callback handler before returning.
			//
			if (lpSock->phy->_verbose)
				printf("Incoming QUIC connection %p\n", Event->NEW_CONNECTION.Connection);
			{
				QUICSocketImpl *lpSock2 = new QUICSocketImpl(lpSock->phy);
				lpSock2->connection = Event->NEW_CONNECTION.Connection;
				lpSock2->type = ZT_PHY_SOCKET_QUIC_IN;
				QUIC_ADDR RemoteAddress;
				uint32_t Size = sizeof(RemoteAddress);
				MsQuic->GetParam(
					Event->NEW_CONNECTION.Connection,
					QUIC_PARAM_CONN_REMOTE_ADDRESS,
					&Size,
					&RemoteAddress
				);
				memcpy(&lpSock2->saddr, &RemoteAddress, Size);
				MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)QUICServerConnectionCallback, lpSock2);
				Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, QUICConfigurationServer);
				if (!QUIC_FAILED(Status))
				{
					QUICEvent *event = new QUICEvent(lpSock2, NULL, ZT_QUIC_SERVER_LISTENER_EVENT, (int)QUIC_LISTENER_EVENT_NEW_CONNECTION);
					lpSock->phy->_emutex.lock();
					lpSock->phy->_equeue.push(event);
					lpSock->phy->_emutex.unlock();
					lpSock->phy->whack();

					if (sslKeyLogFile) {
						if (QUIC_FAILED(Status = MsQuic->SetParam(Event->NEW_CONNECTION.Connection, QUIC_PARAM_CONN_TLS_SECRETS, sizeof(lpSock->TlsSecrets), (uint8_t*)&lpSock->TlsSecrets))) {
							fprintf(stderr, "Couldn't set sslKeyLogFile %s\n", sslKeyLogFile);
						} else {
							lpSock->sslKeyLogFile = sslKeyLogFile;
						}
					}
				}
			}
			break;
		default:
			break;
		}
		return Status;
	}

	static bool fileExists(const char *filename)
	{
		struct stat   buffer;   
		int mRet;
		mRet = stat (filename, &buffer);
		if(0 == mRet)
		{
			if(S_ISREG(buffer.st_mode))
				return true;
		}
		return false;
	}

	inline PhySocket *quicListen(const struct sockaddr *localAddress,void *uptr = (void *)0)
	{
		if (_socks.size() >= ZT_PHY_MAX_SOCKETS)
			return (PhySocket *)0;

		if (!quicInit())
			return (PhySocket *)0;

		if (!QUICConfigurationServer) {
			QUIC_SETTINGS Settings;
			memset(&Settings, 0, sizeof(Settings));
			//
			// Configures the server's idle timeout.
			//
			Settings.IdleTimeoutMs = QUICIdleTimeoutMs;
			Settings.IsSet.IdleTimeoutMs = TRUE;
#ifndef QUIC_STREAM
			Settings.DatagramReceiveEnabled = TRUE;
#endif
			//
			// Configures the server's resumption level to allow for resumption and
			// 0-RTT.
			//
			Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
			Settings.IsSet.ServerResumptionLevel = TRUE;
			//
			// Configures the server's settings to allow for the peer to open a single
			// bidirectional stream. By default connections are not configured to allow
			// any streams from the peer.
			//
			Settings.PeerBidiStreamCount = 1;
			Settings.IsSet.PeerBidiStreamCount = TRUE;

			QUIC_CREDENTIAL_CONFIG_HELPER Config;
			memset(&Config, 0, sizeof(Config));
			Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

			const char* Cert = "/tmp/quic_server.crt";
			const char* KeyFile = "/tmp/quic_server.key";
			const char* Cert2 = "/var/lib/zerotier-one/quic_server.crt";
			const char* KeyFile2 = "/var/lib/zerotier-one/quic_server.key";
			Config.CertFile.CertificateFile = (char*)(Phy::fileExists(Cert)?Cert:Cert2);
			Config.CertFile.PrivateKeyFile = (char*)(Phy::fileExists(KeyFile)?KeyFile:KeyFile2);
			
			Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
			Config.CredConfig.CertificateFile = &Config.CertFile;
			//
			// Allocate/initialize the configuration object, with the configured ALPN
			// and settings.
			//
			QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
			if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(QUICRegistration, &QUICAlpn, 1, &Settings, sizeof(Settings), NULL, &QUICConfigurationServer))) {
				fprintf(stderr, "ConfigurationOpen failed, 0x%x!\n", Status);
				return (PhySocket *)0;
			}

			//
			// Loads the TLS credential part of the configuration.
			//
			if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(QUICConfigurationServer, &Config.CredConfig))) {
				fprintf(stderr, "ConfigurationLoadCredential failed, 0x%x!\n", Status);
				MsQuic->ConfigurationClose(QUICConfigurationServer);
				QUICConfigurationServer = NULL;
				return (PhySocket *)0;
			}
		}

		QUICSocketImpl *lpSock = NULL;

		do {
			QUIC_STATUS Status;
			HQUIC Listener = NULL;

			//
			// Configures the address used for the listener to listen on all IP
			// addresses and the given UDP port.
			//
			QUIC_ADDR Address;
			int Port;
			char Host[1000];
			if (localAddress->sa_family == AF_INET6) {
				struct sockaddr_in6 *addr = (struct  sockaddr_in6 *) localAddress;
				socklen_t Hlen = sizeof(Host);
				Port = ntohs(addr->sin6_port);
				memcpy(&Address.Ipv6, localAddress, sizeof(struct  sockaddr_in6));
				inet_ntop(localAddress->sa_family, &Address.Ipv6.sin6_addr.__in6_u, Host, Hlen);
			} else {
				struct sockaddr_in *addr = (struct  sockaddr_in *) localAddress;
				socklen_t Hlen = sizeof(Host);
				Port = ntohs(addr->sin_port);
				memcpy(&Address.Ipv4, localAddress, sizeof(struct sockaddr_in));
				inet_ntop(localAddress->sa_family, &Address.Ipv4.sin_addr.s_addr, Host, Hlen);
			}
			
			if (_verbose)
				printf("QUIC Listening on UDP %s:%d\n", Host, Port);

			lpSock = new QUICSocketImpl(this);

			//
			// Create/allocate a new listener object.
			//
			if (QUIC_FAILED(Status = MsQuic->ListenerOpen(QUICRegistration, QUICServerListenerCallback, lpSock, &Listener))) {
				fprintf(stderr, "ListenerOpen failed, 0x%x!\n", Status);
				break;
			}

			lpSock->connection = Listener;

			//
			// Starts listening for incoming connections.
			//
			if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &QUICAlpn, 1, &Address))) {
				fprintf(stderr, "ListenerStart failed, 0x%x!\n", Status);
				break;
			}

			try {
				_socks.push_back(PhySocketImpl());
			} catch (...) {
				break;
			}
			PhySocketImpl &sws = _socks.back();
			sws.quic = refQuicSocket(lpSock);
			sws.sock = lpSock->id;
			sws.type = ZT_PHY_SOCKET_QUIC_LISTEN;
			lpSock->s = (PhySocket *)&sws;
			lpSock->type = ZT_PHY_SOCKET_QUIC_LISTEN;
			memcpy(&(lpSock->saddr),localAddress,(localAddress->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
			memcpy(&(sws.saddr), &lpSock->saddr, sizeof(sws.saddr));

			//memcpy(&lpSock->listener_saddr, &lpSock->saddr, sizeof(lpSock->listener_saddr));

			return (PhySocket *)&sws;

		} while (0);

		delete lpSock;
		
		return (PhySocket *)0;
	}

	/**
	 * Wait for activity and handle one or more events
	 *
	 * Note that this is not guaranteed to wait up to 'timeout' even
	 * if nothing happens, as whack() or other events such as signals
	 * may cause premature termination.
	 *
	 * @param timeout Timeout in milliseconds or 0 for none (forever)
	 */
	inline void poll(unsigned long timeout)
	{
		char buf[131072];
		struct sockaddr_storage ss;
		struct timeval tv;
		fd_set rfds,wfds,efds;

		memcpy(&rfds,&_readfds,sizeof(rfds));
		memcpy(&wfds,&_writefds,sizeof(wfds));
#if defined(_WIN32) || defined(_WIN64)
		memcpy(&efds,&_exceptfds,sizeof(efds));
#else
		FD_ZERO(&efds);
#endif

		tv.tv_sec = (long)(timeout / 1000);
		tv.tv_usec = (long)((timeout % 1000) * 1000);
		if (::select((int)_nfds + 1,&rfds,&wfds,&efds,(timeout > 0) ? &tv : (struct timeval *)0) <= 0) {
			
			quicExecEvents();
			quicEmptyDataQueue();

			for(typename std::list<PhySocketImpl>::iterator s(_socks.begin());s!=_socks.end();) {
				if (s->type == ZT_PHY_SOCKET_CLOSED)
					_socks.erase(s++);
				else ++s;
			}

			return;
		}

		if (FD_ISSET(_whackReceiveSocket,&rfds)) {
			char tmp[16];
#if defined(_WIN32) || defined(_WIN64)
			::recv(_whackReceiveSocket,tmp,1,0);
#else
			while(::read(_whackReceiveSocket,tmp,16)==16);
#endif
		}

		quicExecEvents();
		quicEmptyDataQueue();

		for(typename std::list<PhySocketImpl>::iterator s(_socks.begin());s!=_socks.end();) {
			switch (s->type) {

				case ZT_PHY_SOCKET_TCP_OUT_PENDING:
#if defined(_WIN32) || defined(_WIN64)
					if (FD_ISSET(s->sock,&efds)) {
						this->close((PhySocket *)&(*s),true);
					} else // ... if
#endif
					if (FD_ISSET(s->sock,&wfds)) {
						socklen_t slen = sizeof(ss);
						if (::getpeername(s->sock,(struct sockaddr *)&ss,&slen) != 0) {
							this->close((PhySocket *)&(*s),true);
						} else {
							s->type = ZT_PHY_SOCKET_TCP_OUT_CONNECTED;
							FD_SET(s->sock,&_readfds);
							FD_CLR(s->sock,&_writefds);
#if defined(_WIN32) || defined(_WIN64)
							FD_CLR(s->sock,&_exceptfds);
#endif
							try {
								_handler->phyOnTcpConnect((PhySocket *)&(*s),&(s->uptr),true);
							} catch ( ... ) {}
						}
					}
					break;

				case ZT_PHY_SOCKET_TCP_OUT_CONNECTED:
				case ZT_PHY_SOCKET_TCP_IN: {
					ZT_PHY_SOCKFD_TYPE sock = s->sock; // if closed, s->sock becomes invalid as s is no longer dereferencable
					if (FD_ISSET(sock,&rfds)) {
						long n = (long)::recv(sock,buf,sizeof(buf),0);
						if (n <= 0) {
							this->close((PhySocket *)&(*s),true);
						} else {
							try {
								_handler->phyOnTcpData((PhySocket *)&(*s),&(s->uptr),(void *)buf,(unsigned long)n);
							} catch ( ... ) {}
						}
					}
					if ((FD_ISSET(sock,&wfds))&&(FD_ISSET(sock,&_writefds))) {
						try {
							_handler->phyOnTcpWritable((PhySocket *)&(*s),&(s->uptr));
						} catch ( ... ) {}
					}
				}	break;

				case ZT_PHY_SOCKET_TCP_LISTEN:
					if (FD_ISSET(s->sock,&rfds)) {
						memset(&ss,0,sizeof(ss));
						socklen_t slen = sizeof(ss);
						ZT_PHY_SOCKFD_TYPE newSock = ::accept(s->sock,(struct sockaddr *)&ss,&slen);
						if (ZT_PHY_SOCKFD_VALID(newSock)) {
							if (_socks.size() >= ZT_PHY_MAX_SOCKETS) {
								ZT_PHY_CLOSE_SOCKET(newSock);
							} else {
#if defined(_WIN32) || defined(_WIN64)
								{ BOOL f = (_noDelay ? TRUE : FALSE); setsockopt(newSock,IPPROTO_TCP,TCP_NODELAY,(char *)&f,sizeof(f)); }
								{ u_long iMode=1; ioctlsocket(newSock,FIONBIO,&iMode); }
#else
								{ int f = (_noDelay ? 1 : 0); setsockopt(newSock,IPPROTO_TCP,TCP_NODELAY,(char *)&f,sizeof(f)); }
								fcntl(newSock,F_SETFL,O_NONBLOCK);
#endif
								_socks.push_back(PhySocketImpl());
								PhySocketImpl &sws = _socks.back();
								FD_SET(newSock,&_readfds);
								if ((long)newSock > _nfds)
									_nfds = (long)newSock;
								sws.type = ZT_PHY_SOCKET_TCP_IN;
								sws.sock = newSock;
								sws.uptr = (void *)0;
								memcpy(&(sws.saddr),&ss,sizeof(struct sockaddr_storage));
								try {
									_handler->phyOnTcpAccept((PhySocket *)&(*s),(PhySocket *)&(_socks.back()),&(s->uptr),&(sws.uptr),(const struct sockaddr *)&(sws.saddr));
								} catch ( ... ) {}
							}
						}
					}
					break;

				case ZT_PHY_SOCKET_UDP:
					if (FD_ISSET(s->sock, &rfds)) {
#if (defined(__linux__) || defined(linux) || defined(__linux)) && defined(MSG_WAITFORONE)
#define RECVMMSG_WINDOW_SIZE 128
#define RECVMMSG_BUF_SIZE	 1500
						iovec iovs[RECVMMSG_WINDOW_SIZE];
						uint8_t bufs[RECVMMSG_WINDOW_SIZE][RECVMMSG_BUF_SIZE];
						sockaddr_storage addrs[RECVMMSG_WINDOW_SIZE];
						memset(addrs, 0, sizeof(addrs));
						mmsghdr mm[RECVMMSG_WINDOW_SIZE];
						memset(mm, 0, sizeof(mm));
						for (int i = 0; i < RECVMMSG_WINDOW_SIZE; ++i) {
							iovs[i].iov_base = (void*)bufs[i];
							iovs[i].iov_len = RECVMMSG_BUF_SIZE;
							mm[i].msg_hdr.msg_name = (void*)&(addrs[i]);
							mm[i].msg_hdr.msg_iov = &(iovs[i]);
							mm[i].msg_hdr.msg_iovlen = 1;
						}
						for (int k = 0; k < 1024; ++k) {
							for (int i = 0; i < RECVMMSG_WINDOW_SIZE; ++i) {
								mm[i].msg_hdr.msg_namelen = sizeof(sockaddr_storage);
								mm[i].msg_len = 0;
							}
							int received_count = recvmmsg(s->sock, mm, RECVMMSG_WINDOW_SIZE, MSG_WAITFORONE, nullptr);
							if (received_count > 0) {
								for (int i = 0; i < received_count; ++i) {
									long n = (long)mm[i].msg_len;
									if (n > 0) {
										try {
											_handler->phyOnDatagram((PhySocket*)&(*s), &(s->uptr), (const struct sockaddr*)&(s->saddr), (const struct sockaddr*)&(addrs[i]), bufs[i], (unsigned long)n);
										}
										catch (...) {
										}
									}
								}
							}
							else {
								break;
							}
						}
#else
						for (int k = 0; k < 1024; ++k) {
							memset(&ss, 0, sizeof(ss));
							socklen_t slen = sizeof(ss);
							long n = (long)::recvfrom(s->sock, buf, sizeof(buf), 0, (struct sockaddr*)&ss, &slen);
							if (n > 0) {
								try {
									_handler->phyOnDatagram((PhySocket*)&(*s), &(s->uptr), (const struct sockaddr*)&(s->saddr), (const struct sockaddr*)&ss, (void*)buf, (unsigned long)n);
								}
								catch (...) {
								}
							}
							else if (n < 0)
								break;
						}
#endif
					}
					break;

				case ZT_PHY_SOCKET_UNIX_IN: {
#ifdef __UNIX_LIKE__
					ZT_PHY_SOCKFD_TYPE sock = s->sock; // if closed, s->sock becomes invalid as s is no longer dereferencable
					if ((FD_ISSET(sock,&wfds))&&(FD_ISSET(sock,&_writefds))) {
						try {
							_handler->phyOnUnixWritable((PhySocket *)&(*s),&(s->uptr));
						} catch ( ... ) {}
					}
					if (FD_ISSET(sock,&rfds)) {
						long n = (long)::read(sock,buf,sizeof(buf));
						if (n <= 0) {
							this->close((PhySocket *)&(*s),true);
						} else {
							try {
								_handler->phyOnUnixData((PhySocket *)&(*s),&(s->uptr),(void *)buf,(unsigned long)n);
							} catch ( ... ) {}
						}
					}
#endif // __UNIX_LIKE__
				}	break;

				case ZT_PHY_SOCKET_UNIX_LISTEN:
#ifdef __UNIX_LIKE__
					if (FD_ISSET(s->sock,&rfds)) {
						memset(&ss,0,sizeof(ss));
						socklen_t slen = sizeof(ss);
						ZT_PHY_SOCKFD_TYPE newSock = ::accept(s->sock,(struct sockaddr *)&ss,&slen);
						if (ZT_PHY_SOCKFD_VALID(newSock)) {
							if (_socks.size() >= ZT_PHY_MAX_SOCKETS) {
								ZT_PHY_CLOSE_SOCKET(newSock);
							} else {
								fcntl(newSock,F_SETFL,O_NONBLOCK);
								_socks.push_back(PhySocketImpl());
								PhySocketImpl &sws = _socks.back();
								FD_SET(newSock,&_readfds);
								if ((long)newSock > _nfds)
									_nfds = (long)newSock;
								sws.type = ZT_PHY_SOCKET_UNIX_IN;
								sws.sock = newSock;
								sws.uptr = (void *)0;
								memcpy(&(sws.saddr),&ss,sizeof(struct sockaddr_storage));
								try {
									//_handler->phyOnUnixAccept((PhySocket *)&(*s),(PhySocket *)&(_socks.back()),&(s->uptr),&(sws.uptr));
								} catch ( ... ) {}
							}
						}
					}
#endif // __UNIX_LIKE__
					break;

				case ZT_PHY_SOCKET_FD: {
					ZT_PHY_SOCKFD_TYPE sock = s->sock;
					const bool readable = ((FD_ISSET(sock,&rfds))&&(FD_ISSET(sock,&_readfds)));
					const bool writable = ((FD_ISSET(sock,&wfds))&&(FD_ISSET(sock,&_writefds)));
					if ((readable)||(writable)) {
						try {
							//_handler->phyOnFileDescriptorActivity((PhySocket *)&(*s),&(s->uptr),readable,writable);
						} catch ( ... ) {}
					}
				}	break;

				default:
					break;

			}

			if (s->type == ZT_PHY_SOCKET_CLOSED)
				_socks.erase(s++);
			else ++s;
		}
	}

	inline void quicEmptyDataQueue()
	{
		_pmutex.lock();

		while (!_pqueue.empty()) {
			LP_QUIC_RECEIVED_DATA data = _pqueue.front();
			_pqueue.pop();
			_pmutex.unlock();
			if (data->quic->type != ZT_PHY_SOCKET_CLOSED && data->quic->type != ZT_PHY_SOCKET_QUIC_SHUTTINGDOWN ) {
				try {
					_handler->phyOnDatagram(data->s, (void **)&data->quic, (const struct sockaddr*)&data->from, (const struct sockaddr*)&data->to, data->data->Buffer, data->data->Length);
				} catch (...) {
					if (_verbose)
						printf("Exception caught when phyOnDatagram([Sock][%p][quic][%p])", data->s, data->quic);
				}
			}
			derefQuicSocket(data->quic);
			free(data->data);
			free(data);
			_pmutex.lock();
		}
		_pmutex.unlock();
	}

	inline void quicExecEvents() 
	{
		_emutex.lock();
		while (!_equeue.empty()) {
			QUICEvent *event = _equeue.front();
			_equeue.pop();
			_emutex.unlock();

			switch (event->type)
			{
			case ZT_QUIC_CLIENT_CONNECTION_EVENT:
				quicExecClientConnectionEvents(event->quic, event->uptr, (QUIC_CONNECTION_EVENT_TYPE)event->event);
				break;
			case ZT_QUIC_CLIENT_STREAM_EVENT:
				quicExecClientStreamEvents(event->quic, event->uptr, (QUIC_STREAM_EVENT_TYPE)event->event);
				break;
			case ZT_QUIC_SERVER_LISTENER_EVENT:
				quicExecServerListenerEvents(event->quic, event->uptr, (QUIC_LISTENER_EVENT_TYPE)event->event);
				break;
			case ZT_QUIC_SERVER_CONNECTION_EVENT:
				quicExecServerConnectionEvents(event->quic, event->uptr, (QUIC_CONNECTION_EVENT_TYPE)event->event);
				break;
			case ZT_QUIC_SERVER_STREAM_EVENT:
				quicExecServerStreamEvents(event->quic, event->uptr, (QUIC_STREAM_EVENT_TYPE)event->event);
				break;
			
			default:
				break;
			}
			
			delete event;
			_emutex.lock();
		}
		_emutex.unlock();
	}

	static void quicShutdown(QUICSocketImpl *q)
	{
		if (!q)
			return;
		PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(q->s));
		if (q->stream) {
			MsQuic->StreamClose(q->stream);
			q->stream = NULL;
		}

		if (q->connection) {
			MsQuic->ConnectionShutdown(q->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
		}

		q->type = ZT_PHY_SOCKET_QUIC_SHUTTINGDOWN;
		sws.type = ZT_PHY_SOCKET_QUIC_SHUTTINGDOWN;
	}

	/**
	 * @param sock Socket to close
	 * @param callHandlers If true, call handlers for TCP connect (success: false) or close (default: true)
	 */
	inline void close(PhySocket *sock,bool callHandlers = true)
	{
		if (!sock)
			return;
		PhySocketImpl &sws = *(reinterpret_cast<PhySocketImpl *>(sock));
		if (sws.type == ZT_PHY_SOCKET_CLOSED)
			return;

		if (sws.type >= ZT_PHY_SOCKET_QUIC_OUT_PENDING && sws.type <= ZT_PHY_SOCKET_QUIC_SHUTTINGDOWN) {
			if (sws.quic) {
				derefQuicSocket(sws.quic);
			}
			sws.sock = -1;
			sws.quic = NULL;
			sws.type = ZT_PHY_SOCKET_CLOSED;
			return;
		}

		FD_CLR(sws.sock,&_readfds);
		FD_CLR(sws.sock,&_writefds);
#if defined(_WIN32) || defined(_WIN64)
		FD_CLR(sws.sock,&_exceptfds);
#endif

		if (sws.type != ZT_PHY_SOCKET_FD) {
			if (_verbose) {
				if (sws.type == ZT_PHY_SOCKET_TCP_LISTEN) {
					int Port;
					char Host[1000];
					if (((struct sockaddr *)&sws.saddr)->sa_family == AF_INET6) {
						struct sockaddr_in6 *addr = (struct  sockaddr_in6 *) &sws.saddr;
						socklen_t Hlen = sizeof(Host);
						Port = ntohs(addr->sin6_port);
						inet_ntop(AF_INET6, &addr->sin6_addr.__in6_u, Host, Hlen);
					} else {
						struct sockaddr_in *addr = (struct  sockaddr_in *) &sws.saddr;
						socklen_t Hlen = sizeof(Host);
						Port = ntohs(addr->sin_port);
						inet_ntop(AF_INET, &addr->sin_addr.s_addr, Host, Hlen);
					}
					
					printf("Closing TCP Listener %s:%d\n", Host, Port);
				} else if (sws.type == ZT_PHY_SOCKET_UDP) {
					int Port;
					char Host[1000];
					if (((struct sockaddr *)&sws.saddr)->sa_family == AF_INET6) {
						struct sockaddr_in6 *addr = (struct  sockaddr_in6 *) &sws.saddr;
						socklen_t Hlen = sizeof(Host);
						Port = ntohs(addr->sin6_port);
						inet_ntop(AF_INET6, &addr->sin6_addr.__in6_u, Host, Hlen);
					} else {
						struct sockaddr_in *addr = (struct  sockaddr_in *) &sws.saddr;
						socklen_t Hlen = sizeof(Host);
						Port = ntohs(addr->sin_port);
						inet_ntop(AF_INET, &addr->sin_addr.s_addr, Host, Hlen);
					}
					
					printf("Closing UDP Binder %s:%d\n", Host, Port);
				}
			}
			ZT_PHY_CLOSE_SOCKET(sws.sock);
		}

#ifdef __UNIX_LIKE__
		if (sws.type == ZT_PHY_SOCKET_UNIX_LISTEN)
			::unlink(((struct sockaddr_un *)(&(sws.saddr)))->sun_path);
#endif // __UNIX_LIKE__

		if (callHandlers) {
			switch(sws.type) {
				case ZT_PHY_SOCKET_TCP_OUT_PENDING:
					try {
						_handler->phyOnTcpConnect(sock,&(sws.uptr),false);
					} catch ( ... ) {}
					break;
				case ZT_PHY_SOCKET_TCP_OUT_CONNECTED:
				case ZT_PHY_SOCKET_TCP_IN:
					try {
						_handler->phyOnTcpClose(sock,&(sws.uptr));
					} catch ( ... ) {}
					break;
				case ZT_PHY_SOCKET_UNIX_IN:
#ifdef __UNIX_LIKE__
					try {
						_handler->phyOnUnixClose(sock,&(sws.uptr));
					} catch ( ... ) {}
#endif // __UNIX_LIKE__
					break;
				default:
					break;
			}
		}

		// Causes entry to be deleted from list in poll(), ignored elsewhere
		sws.type = ZT_PHY_SOCKET_CLOSED;

		if ((long)sws.sock >= (long)_nfds) {
			long nfds = (long)_whackSendSocket;
			if ((long)_whackReceiveSocket > nfds)
				nfds = (long)_whackReceiveSocket;
			for(typename std::list<PhySocketImpl>::iterator s(_socks.begin());s!=_socks.end();++s) {
				if ((s->type != ZT_PHY_SOCKET_CLOSED)&&((long)s->sock > nfds))
					nfds = (long)s->sock;
			}
			_nfds = nfds;
		}
	}

	inline void removeSock(const PhySocketImpl &sws)
	{
		for(typename std::list<PhySocketImpl>::iterator s(_socks.begin());s!=_socks.end();++s) {
			if (sws.id == s->id) {
				_socks.erase(s);
				break;
			}
		}
	}
};

} // namespace ZeroTier

#endif
