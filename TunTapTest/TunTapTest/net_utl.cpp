#include "net_utl.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include <assert.h>

#ifndef WIN32
	#include <net/if.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <sys/ioctl.h>
	#include <sys/socket.h>
	#include <unistd.h>
	#include <errno.h>
	#include <netinet/in.h>
    #include <arpa/nameser.h>
    #include <resolv.h>
#endif

#include <string>
#include <list>

using namespace std;


#ifdef WIN32
	#pragma comment(lib,"ws2_32.lib")
#endif

void sys_msleep(int ms)
{
#ifdef WIN32
	if (ms == 0) {
		++ms;
	}
	Sleep(ms);
#else
	usleep(ms * 1000);
#endif
}

uint32 sys_time()
{
	return (uint32)(time(NULL));
}

/*
* timezone information is stored outside the kernel so tzp isn't used anymore.
*/
static int sys_getTimeOfDay(struct timeval * tp, struct timezone * tzp)
{
#ifdef WIN32
	static const uint64 epoch = 116444736000000000ui64;
	FILETIME    file_time;
	SYSTEMTIME  system_time;
	ULARGE_INTEGER ularge;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	ularge.LowPart = file_time.dwLowDateTime;
	ularge.HighPart = file_time.dwHighDateTime;

	tp->tv_sec = (long) ((ularge.QuadPart - epoch) / 10000000L);
	tp->tv_usec = (long) (system_time.wMilliseconds * 1000);

	return 0;
#else
	return gettimeofday(tp, tzp);
#endif
}

uint64 g_uCachedTimeMs64 = sys_getMs64();
uint64 sys_getMs64()
{
	struct timeval tv;
	sys_getTimeOfDay(&tv, NULL);
	uint64 uMs64 = (int64)tv.tv_sec  * 1000 + tv.tv_usec / 1000;
	g_uCachedTimeMs64 = uMs64;
	return uMs64;
}

uint32 sys_getMs()
{ 
	return (uint32)sys_getMs64(); 
}

#ifdef WIN32
static uint64 getSysTime64__()
{
	uint64 tmNow = 0;
	struct _timeb timebuffer;
	_ftime(&timebuffer);
	tmNow = timebuffer.time;
	tmNow *= 1000;
	tmNow += timebuffer.millitm;
	return tmNow;
}
#else
static uint64 getSysTime64__()
{
	uint64 tmNow = 0;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	tmNow = tv.tv_sec;
	tmNow *= 1000;
	tmNow += tv.tv_usec/1000;
	return tmNow;
}
#endif

int setReuse(socket_t nSockFd)
{
	const int one = 1;
#ifdef SO_REUSEADDR
	if (setsockopt(nSockFd, SOL_SOCKET, SO_REUSEADDR,
		(const char*)&one, sizeof(one)) < 0) {
		return -1;
	}
#endif
#ifdef SO_REUSEPORT
	if (setsockopt(nSockFd, SOL_SOCKET, SO_REUSEPORT,
		(const char*)&one, sizeof(one)) < 0) {
		return -1;
	}
#endif
	return 0;
}

int setRcvTimeOut(socket_t nSocket, int nSecond)
{
#ifdef WIN32
	int nTimeOut = nSecond * 1000;
	int nRet;
	nRet = setsockopt(nSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&nTimeOut, sizeof(nTimeOut));
	if (nRet == SOCKET_ERROR) {
		out_err(("Set SO_RCVTIMEO error\n"));
		return -1;
	}
	return 0;
#else
	struct timeval tv;
	int nRet;
	tv.tv_sec = nSecond;
	tv.tv_usec = 0;

	nRet = setsockopt(nSocket, SOL_SOCKET, SO_RCVTIMEO, (void*)&tv, sizeof(tv));
	if (nRet == -1) {
		out_err(("Set SO_RCVTIMEO error\n"));
		return -1;
	}
	return 0;
#endif
}

int setSndTimeOut(socket_t nSocket, int nSecond)
{
#ifdef WIN32
	int nTimeOut = nSecond * 1000;
	int nRet;
	nRet = setsockopt(nSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&nTimeOut, sizeof(nTimeOut));
	if (nRet == SOCKET_ERROR) {
		out_err(("Set SO_SNDTIMEO error\n"));
		return -1;
	}
	return 0;
#else
	struct timeval tv;
	int nRet;
	tv.tv_sec = nSecond;
	tv.tv_usec = 0;

	nRet = setsockopt(nSocket, SOL_SOCKET, SO_SNDTIMEO, (void*)&tv, sizeof(tv));
	if (nRet == -1) {
		out_err(("Set SO_RCVTIMEO error\n"));
		return -1;
	}
	return 0;
#endif
}

bool isBlocked(socket_t nSocket)
{
#ifdef _WIN32
	int e = WSAGetLastError();
	if (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY || e == WSAEINVAL || e == WSAENOTCONN ) {
		return true;
	} else {
		return 0;
	}
#else
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EALREADY || errno == ENOTCONN) {
		return true;
	} else {
		return false;
	}
#endif
}

socket_t connectTo(sockaddr *pSockAddr, bool isNonBlock, bool isReUseAddr)
{
	socket_t socketFd = 0;
	int nRet;

	socketFd = ::socket(AF_INET, SOCK_STREAM, 0);
	if (socketFd == -1) {
		out_err(("socket():%s", ""));
		return -1;
	}
	if (isReUseAddr) {
		setReuse(socketFd);
	}
	if (isNonBlock) {
		setNonblock(socketFd);
		nRet = connect(socketFd, pSockAddr, sizeof(sockaddr_in));
		return socketFd; // nRet maybe < 0)
	} else {
		nRet = ::connect(socketFd, pSockAddr, sizeof(sockaddr_in));
		if (nRet == -1) {
			out_err(("Failed to connect to other side.\n"));
			closeSocket(socketFd);
			return -1;
		}
		return socketFd;
	}
}

socket_t listenSocket(sockaddr *pSockAddr, bool fReUsedAddr/*=false*/)
{
	socket_t socketFd = 0;
	int nRet;
	socketFd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socketFd == -1) {
		out_err(("socket():%s", ""));
		return -1;
	}
	if (fReUsedAddr) {
		setReuse(socketFd);
	}
	nRet = bind(socketFd, pSockAddr, sizeof(sockaddr_in));
	if (nRet == -1) {
		out_err(("::connect():%s", ""));
		closeSocket(socketFd);
		return -1;
	}
	nRet = listen(socketFd, 20);
	if (nRet == -1) {
		out_err(("::connect():%s", ""));
		closeSocket(socketFd);
		return -1;
	}
	return socketFd;
}

int setNonblock(socket_t nSockFd)
{
#ifdef WIN32
	unsigned long fl = 1;
	if (ioctlsocket(nSockFd, FIONBIO, &fl) < 0)
		return -1;
#else
	int fl = fcntl(nSockFd, F_GETFL);
	if (fl < 0)
		return -1;
	if (fcntl(nSockFd, F_SETFL, fl | O_NONBLOCK) < 0)
		return -1;
#endif
	return 0;
}

socket_t openUdp(struct sockaddr* pSockAddr, bool fReUsedAddr/*=false*/)
{
	socket_t sockFd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockFd < 0) {
		out_err(("call socket() error:"));
		return -1;
	}

	/* bind address and port to socket */
	if(bind(sockFd, pSockAddr, sizeof(struct sockaddr_in)) == -1) {
		out_err(("call bind() error:"));
		closeSocket(sockFd);
		return -1;
	}
	out_vbs(("Udp Port:%u opened\n", ntohs(((struct sockaddr_in*)pSockAddr)->sin_port)));
	
	return sockFd;
}

int initNet()
{
#ifdef WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
		return -1;

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		WSACleanup();
		return -1;
	}
	return 0;
#else
	return 0;
#endif
}

#ifdef WIN32
uint64 getSysTime64()
{
	uint64 tmNow = 0;
	struct _timeb timebuffer;
	_ftime(&timebuffer);
	tmNow = timebuffer.time;
	tmNow *= 1000;
	tmNow += timebuffer.millitm;
	return tmNow;
}
#else
uint64 getSysTime64()
{
	uint64 tmNow = 0;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	tmNow = tv.tv_sec;
	tmNow *= 1000;
	tmNow += tv.tv_usec/1000;
	return tmNow;
}
#endif

const char *inet_ntoa2(unsigned int uIp)
{
	in_addr addr;
	addr.s_addr = uIp;
	return inet_ntoa(addr);
}

int setSockSendBuff(socket_t nSocket, int nNrKb) 
{
	for (int i = 1; i <= nNrKb; ++i) {
		int nBuffSize = 1024 * i;
		int nRet = setsockopt(nSocket, SOL_SOCKET, SO_SNDBUF, (char *)&nBuffSize, sizeof(int));
		nRet = nRet;
		//printf("nRet:%d , nSize:%d\n", nRet, nBuffSize);
	}
	return 0;
}

int setSockRecvBuff(socket_t nSocket, int nNrKb) 
{
	int nRet = 0;
	int nBuffSize = 0;
	for (int i = 1; i <= nNrKb; ++i) {
		nBuffSize = 1024 * i;
		nRet = setsockopt(nSocket, SOL_SOCKET, SO_RCVBUF, (char *)&nBuffSize, sizeof(int));
		nRet = nRet;
	}
	return 0;
}

int isSendable(socket_t nSocket, int nTimeOutMs)
{
	struct timeval tv;
	fd_set wfds;
	FD_ZERO(&wfds);
	FD_SET(nSocket, &wfds);
	tv.tv_sec = nTimeOutMs / 1000;
	tv.tv_usec = (nTimeOutMs % 1000) * 1000 ;
	return select(nSocket + 1, NULL, &wfds, NULL, &tv) == 1;
}

int isReadable(socket_t nSocket, int nTimeOutMs)
{
	struct timeval tv;
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(nSocket, &rfds);
	tv.tv_sec = nTimeOutMs / 1000;
	tv.tv_usec = (nTimeOutMs % 1000) * 1000 ;
	return select(nSocket + 1, &rfds, NULL, NULL, &tv) == 1;
}

/**
 * Parse IP and port in a sting like "192.3.4.5:2345"
 * aways return 0;
 */
int parseIpPort(const char* pszIpPort, uint32* puIp, uint16* puPort)
{
    char achBuffer[255] = {0};
    char* pPos;
#ifndef WIN32
	res_init();
#endif

    assert(puPort);
    strcat(achBuffer, pszIpPort);
    pPos = strchr(achBuffer, ':');
    if (pPos) {
        *pPos = 0;
        *puIp = inet_addr(achBuffer);
        if (*puIp == INADDR_NONE) {
            struct hostent *host;
            if ((host = gethostbyname(achBuffer)) != NULL) {
                *puIp = *((unsigned long*)host->h_addr_list[0]);
            }
        }
        if (puPort) {
            *puPort = atoi(pPos + 1);
        }
    } else {
		struct hostent *host;		
		if ((host = gethostbyname(achBuffer)) != NULL) {
			*puIp = *((unsigned long*)host->h_addr_list[0]);		
		}
    }
    return 0;
}

std::string sys_getHex(const char* pData, int nLen)
{
	char aBuff[1024];
	static char aHex[]="0123456789ABCDEF";
	int i = 0;
	int k = 0;
	for (i = 0; i < nLen; ++i) {
		unsigned char ch = (unsigned char)(pData[i]);
		if (k < 1020) {
			aBuff[k] = aHex[ch >> 4];
			aBuff[k+1] = aHex[ch & 0xF];
			k+=2;
			if (i % 4 == 3) {
				aBuff[k] = ' ';
				++k;
			}
		} else {
			break;
		}
	}
	aBuff[k] = 0;
	return std::string(aBuff);
}

int sys_printHex(const char* pData, int nLen, const char* pPrompt, int nPrintAddr, int nCharPerLine, int nCharGroup)
{
	char aBuff[256];
	static char aHex[]="0123456789ABCDEF";
	int i,j;
	int nLines = nLen / nCharPerLine + 1;
	int nChars;
	if (pPrompt) {
		printf("%s", pPrompt);
	}
	for(j = 0; j < nLines; ++j) {
		int k = 0; 
		nChars = nLen - (j * nCharPerLine);
		nChars = nChars > nCharPerLine ? nCharPerLine : nChars;
		if (nChars <= 0) {
			break; 
		}   
		// Dump the address
		memset(aBuff, ' ', 255);
		if (nPrintAddr) {
			k = sprintf(aBuff, "0x%.4x[%.5d]",  j * nCharPerLine, j * nCharPerLine);
			aBuff[k] = ' ';
		}
		// Dump the HEX.
		for(i = 0; i < nCharPerLine; ++i) {
			if (i % nCharGroup == 0) {
				k++;
			}
			if (i < nChars) {
				unsigned char ch = *(pData + j * nCharPerLine + i);
				aBuff[k] = aHex[ch >> 4];
				aBuff[k+1] = aHex[ch & 0xF];
			}   
			k += 2;
		}
		// char dump
		++k;
		aBuff[ k++ ]='-'; aBuff[ k++ ]='-'; k++;
		for(i = 0; i < nChars; ++i) {
			if (i % nCharGroup == 0) {
				k++;
			}
			unsigned char ch = *(pData + j * nCharPerLine + i);
			if (ch < 200 && isprint(ch)) {
				aBuff[k] = ch;
			} else {
				aBuff[k] = '.';
			}
			++k;
		}
		aBuff[k] = 0;
		aBuff[k + 1] = 0;
		puts(aBuff);
	}
	return 0;
}

/** Debug Log */

#define MSGBUFF_LEN (4096)
class TvuUdpDebug {
public:
	socket_t _nSockFd;
	uint32 _uLastInSec;
	sockaddr_in _saPeer;

	char _achMsgIn[MSGBUFF_LEN];
	int _nMsgInLen;
	uint16 _uSn;
public:
	TvuUdpDebug();
	~TvuUdpDebug();
	// server
	int va_send(uint32 uSubSys, uint32 uMask, const char* pFormat, va_list vaArgs);
	int send(char* pData, int nLen);
	int recv(uint32 uCurrSec);
};

int getAllIps(list<string>& rlstIps, bool bIsT)
{
	rlstIps.clear();
	list<IpNameInfo> olstIpNames;
	getAllIpNames(olstIpNames, bIsT);
	list<IpNameInfo>::iterator it;
	for (it = olstIpNames.begin(); it != olstIpNames.end(); ++it) {
		rlstIps.push_back(it->strIp);
	}
	return 0;
}

#ifdef WIN32

int getAllIpNames(list<IpNameInfo>& rlstIpNames, bool bIsT)
{
	rlstIpNames.clear();
	char achHostName[256]; 
	int nRet = gethostname(achHostName, sizeof(achHostName));
	if (nRet == -1) {
		return 0;
	} 
	struct hostent *host = gethostbyname(achHostName); 
	int i = 0;
	if (host != NULL) { 
		for (i=0; ; i++ ) { 
			string strIp = string(inet_ntoa( *(in_addr*)host-> h_addr_list[i]));
			if (strIp != "127.0.0.1" && strIp !="192.168.3.1") {
				IpNameInfo oInfo;
				oInfo.strIp = strIp;
				oInfo.uIp = inet_addr(strIp.c_str());
				oInfo.fIsPppIf = false;
				oInfo.nSlot = 0;
				rlstIpNames.push_back(oInfo);
			}
			if ( host-> h_addr_list[i] + host-> h_length >= host-> h_name) {
				break;
			}
		} 
	}
	return 0;
}
#else

std::string queryIf(int fd, char* name, uint32 *puFlag)
{
	struct ifreq req;
	strncpy( req.ifr_name, name, sizeof(req.ifr_name) );
	struct sockaddr_in *sin;

	sin = (struct sockaddr_in *)&req.ifr_addr;
	string strIp;
	if(ioctl( fd, SIOCGIFADDR, &req) == 0 ) {
		strIp = string(inet_ntoa(sin->sin_addr));
	} else {
		perror("ioctl error: ");
	}

	if( ioctl( fd, SIOCGIFFLAGS, &req) == 0 ) {
		*puFlag = req.ifr_flags;
		// printf("%s %s 0x%X\n", name, strIp.c_str(), req.ifr_flags) ;
	} else { 
		perror("ioctl error: ");
	}

	return strIp;

	//sin = (struct sockaddr_in *)&req.ifr_dstaddr;
	//if( ioctl( fd, SIOCGIFDSTADDR, &req) == 0 )
	//    printf("%s\n", inet_ntoa(sin->sin_addr) );
	//else
	//    perror("ioctl error: ");

	//	sin = (struct sockaddr_in *)&req.ifr_netmask;
	//if( ioctl( fd, SIOCGIFNETMASK, &req) == 0 ) {
	//	return string(inet_ntoa(sin->sin_addr));
	//} else {
	//	return string();
	//}
	//return 0;
}

int getAllIpNames(list<IpNameInfo>& rlstIpNames, bool bIsT)
{
	struct ifconf conf;
	struct ifreq *req;

	int sockfd;
	int i;

	if((sockfd = socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		//printf("Socket Error:%s a",strerror(errno));
		return -1;
	}

	int len = 64 * sizeof(struct ifreq);
	char* buf = (char*)malloc(len);
	conf.ifc_len = len;
	conf.ifc_buf = buf;

	if(ioctl(sockfd,SIOCGIFCONF,&conf)==-1)
	{
		//printf("ioctl Error:%s a",strerror(errno));
		return -1;
	}

	for(i = conf.ifc_len / sizeof(struct ifreq), req = conf.ifc_req; i > 0; req++, i--)
	{
		//printf("Device Name = %s\n",req->ifr_name);
		uint32 uFlag = 0;
		std::string strIp = queryIf(sockfd, req->ifr_name, &uFlag);
        //192.168.3.1 is the IP of hotspot
		if (strIp.size() > 3 && strIp != "127.0.0.1" && strIp != "192.168.3.1") {
			IpNameInfo oInfo;
			oInfo.strIp = strIp;
			oInfo.strName = req->ifr_name;
			oInfo.uIp = inet_addr(strIp.c_str());
			oInfo.fIsPppIf = (uFlag & IFF_POINTOPOINT) ? true : false;
			oInfo.fIsReady = true;

			oInfo.nSlot = 0;
			rlstIpNames.push_back(oInfo);
		}
	}
	free(buf);
	close(sockfd);
	return 0;
}
#endif
