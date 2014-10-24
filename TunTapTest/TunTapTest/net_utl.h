#ifndef ___NET_UTL_H__
#define ___NET_UTL_H__

#ifdef WIN32
	#define _CRT_SECURE_NO_WARNINGS
	#include <winsock2.h>
	#include <windows.h>
	#include <ws2tcpip.h>
#else
	#include <sys/types.h>
	#include <sys/socket.h>
    #include <sys/un.h>    
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <unistd.h>
	#include <fcntl.h>
	#include <netdb.h>
	#include <sys/times.h>
	#include <sys/time.h>
#endif

#include <stdlib.h>

#include <sys/timeb.h>
#include <string>

#ifdef WIN32
	#define socket_t SOCKET
	#define socketlen_t int
	#define closeSocket(x) ::closesocket(x)
#else
	#define INVALID_SOCKET -1
	#define socket_t int
	#define socketlen_t socklen_t
	#define closeSocket(x) ::close(x)
	#define INVALID_SOCKET -1
#endif

typedef unsigned int   uint32;
typedef unsigned short uint16;
typedef int            int32;
typedef short          int16;
typedef unsigned char  uint8;

#ifdef WIN32
	typedef __int64          int64;
	typedef unsigned __int64 uint64;
#else
	typedef unsigned long long int uint64;
	typedef          long long int int64;
#endif

#include <string>
#include <list>

struct IpNameInfo {
	std::string strName;
	std::string strIp;
	uint32 uIp;
	int  nSlot;
	bool fIsPppIf;
	bool fIsReady;
};

#ifdef WIN32
	#include <windows.h>
	#include <process.h>
	#define MUTEX_T CRITICAL_SECTION
	#define MUTEX_INIT(l) InitializeCriticalSection(l)
	#define MUTEX_LOCK(l) EnterCriticalSection(l)
	#define MUTEX_UNLOCK(l) LeaveCriticalSection(l)
	#define MUTEX_DESTROY(l) DeleteCriticalSection(l)
#else
	#include <pthread.h>
	#define MUTEX_T pthread_mutex_t
	#define MUTEX_INIT(l) pthread_mutex_init(l, NULL)
	#define MUTEX_LOCK(l) pthread_mutex_lock(l)
	#define MUTEX_UNLOCK(l) pthread_mutex_unlock(l)
	#define MUTEX_DESTROY(l) pthread_mutex_destroy(l)
	#include <dirent.h>
#endif

struct ThreadMsgData
{
	uint8 uCmd;
};



/* Hack the user mesage for RTT.*/
/* Message ID is 4 and 5 */

#ifdef WIN32
	#pragma warning(disable:4200) // zero-sized array in 
#endif

int getAllIps(std::list<std::string>& rlstIps, bool bIsT = true);
int getAllIpNames(std::list<IpNameInfo>& rlstIpNames, bool bIsT = true);

#define out_err(x)  { if(1 & 0x1) {printf x;}}
#define out_vbs(x)  { if(0 & 0x2) {printf x;}}

uint32 sys_getMs();
uint64 sys_getMs64();

extern uint64 g_uCachedTimeMs64;
inline static uint32 sys_getCacheMs() {return (uint32)g_uCachedTimeMs64;}
inline static uint64 sys_getCacheMs64() { return g_uCachedTimeMs64;}

int setRcvTimeOut(socket_t nSocket, int nSecond);
int setSndTimeOut(socket_t nSocket, int nSecond);
socket_t connectTo(sockaddr *pSockAddr, bool isNonBlock, bool isReUseAddr);
socket_t listenSocket(sockaddr *pSockAddr, bool fReUsedAddr=false);
int setNonblock(socket_t nSockFd);
int setReuse(socket_t nSockFd);
int setSockSendBuff(socket_t nSocket, int nNrKb);
int setSockRecvBuff(socket_t nSocket, int nNrKb);
int isSendable(socket_t nSocket, int nTimeOutMs);
int isReadable(socket_t nSocket, int nTimeOutMs);
socket_t openUdp(struct sockaddr* pSockAddr, bool fReUsedAddr=false);
int parseIpPort(const char* pszIpPort, uint32* puIp, uint16* puPort);
int initNet();

const char *inet_ntoa2(unsigned int uIp);
void sys_msleep(int ms);
uint32  sys_gettickcount();
uint64 sys_gettickcount64();
uint32 sys_time();
int sys_printHex(const char* pData, int nLen, const char* pPrompt=NULL, int nPrintAddr=1, int nCharPerLine=16, int nCharGroup=2);
std::string sys_getHex(const char* pData, int nLen);

bool isBlocked(socket_t nSocket);
int getSockErrNo(socket_t nSocket);
char* getSockErrStr();
bool socketNormalError(socket_t _nSocket); //justin add 

#ifdef WIN32
	#define PI64 "%I64"
	#define PI64Hex "%016I64"
#else
	#define PI64 "%ll"
	#define PI64Hex "%016ll"
#endif

#ifndef max
	#define sys_max(a, b)   ((a) > (b) ? (a) : (b))
	#define sys_min(a, b)   ((a) < (b) ? (a) : (b))
#endif

#endif /* ___NET_UTL_H__ */

