#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
using namespace std;

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

	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <linux/if_tun.h>
#endif
#include "sys_utl.h"
#include <map>

#define ADAPTER_KEY	"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TUNTAP_COMPONENT_ID "tap0901"

#define TAP_CONTROL_CODE( request, method ) ( \
	CTL_CODE( (FILE_DEVICE_UNKNOWN), (request), (method), 0) \
	)

class ShareData
{
private:
    struct IpPort {
        uint32 uIp;
        uint16 uPort;
        uint32 uSec;
    };
    typedef std::map<uint32, IpPort> MapIp2Ipport;
    MapIp2Ipport _mapIp2Ipport;
    MUTEX_T _lock;
public:
    ShareData() {
         MUTEX_INIT(&_lock);
    }
    ~ShareData() {
        MUTEX_DESTROY(&_lock);
    }
    void addMap(uint32 uFromLocalIp, uint32 uFromExtIp, uint16 uFromExtPort) {
        uint32 uSec = (uint32)(sys_getMs64() / 1000);
        IpPort oIpPort = { uFromExtIp, uFromExtPort, uSec};

        MUTEX_LOCK(&_lock);
        _mapIp2Ipport[uFromLocalIp] = oIpPort;
        MUTEX_UNLOCK(&_lock);

        return; 
    }
    int getExtIpPort(uint32 uFromLocalIp, uint32* puFromExtIp, uint16* puFromExtPort) {
        MapIp2Ipport::iterator it;

        MUTEX_LOCK(&_lock);
        it = _mapIp2Ipport.find(uFromLocalIp);
        if (it != _mapIp2Ipport.end()) {
            *puFromExtIp = it->second.uIp;
            *puFromExtPort = it->second.uPort;
        }
        MUTEX_UNLOCK(&_lock);
        return 0;
    }
    int clean();
};

int ShareData::clean()
{
    MapIp2Ipport::iterator it;
    for (it = _mapIp2Ipport.begin(); it != _mapIp2Ipport.end(); ++it) {
        
    }
    return 0;
}

string get_tuntap_ComponentId()
{
	string ret;
	long status;
	HKEY hAdapterKey = NULL;
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ | KEY_WRITE, &hAdapterKey);
	if(status != ERROR_SUCCESS)
	{
		printf("open key[%s] failed\n", ADAPTER_KEY);
	}
	int index = 0;
	char buffer[256];
	DWORD bufsize = sizeof(buffer);
	HKEY hUnitKey = NULL;
	while(RegEnumKeyEx(hAdapterKey, index, buffer, &bufsize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
	{
		status = RegOpenKeyEx(hAdapterKey, buffer, 0, KEY_READ | KEY_WRITE, &hUnitKey);
		if(status != ERROR_SUCCESS)
		{
			printf("open key[%s] failed\n", buffer);
			index++;
			memset(buffer, 0, sizeof(buffer));
			bufsize = sizeof(buffer);
			continue;
		}
		char component_id[256] = {0};
		DWORD len = sizeof(component_id);
		DWORD dType;
		status = RegQueryValueEx(hUnitKey, "ComponentId", 0, &dType, (LPBYTE)component_id, &len);
		if(strncmp(component_id, TUNTAP_COMPONENT_ID, len) == 0) // found tun device
		{
			char instance_id[256];
			DWORD ins_len = sizeof(instance_id);
			status = RegQueryValueEx(hUnitKey, "NetCfgInstanceId", 0, &dType, (LPBYTE)instance_id, &ins_len);
			printf("tun device found, instance id=%s\n", instance_id);
			ret = instance_id;
			break;
		}

		index++;
		memset(buffer, 0, sizeof(buffer));
		bufsize = sizeof(buffer);
	}
	return ret;
}

HANDLE open_tun(char *ip , char *netmask)
{
	string component_id = get_tuntap_ComponentId();
	char device_path[256] = {0};
	sprintf_s(device_path, sizeof(device_path), "\\\\.\\Global\\%s.tap", component_id.c_str());
	HANDLE handle = CreateFile(	device_path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
		NULL);
	if(handle == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed on TAP device: %s\n", device_path);
	}
	DWORD active = 1;
	DWORD len;
	int status = DeviceIoControl(handle, 
		TAP_CONTROL_CODE(6, 0),	// TAP_IOCTL_SET_MEDIA_STATUS
		&active,
		sizeof(active),
		&active,
		sizeof(active),
		&len,
		NULL
		);
	if(status == 0)
	{
		printf("WARNING: The TAP-Windows driver rejected a TAP_WIN_IOCTL_SET_MEDIA_STATUS DeviceIoControl call.\n");
		return NULL;
	}

	int configtun[3] = {0};// {0x01000b0a, 0x00000b0a, 0x0000ffff}; // IP, NETWORK, MASK
	configtun[0] = inet_addr(ip);
	configtun[1] = inet_addr(ip);
	char *p = (char*)(configtun+1);
	*(p+3) = 0;
	configtun[2] = inet_addr(netmask);
	for(int i = 0; i < sizeof(configtun); i++)
	{
		printf("%02x ", (uint8)*((char*)configtun+i));
	}
	printf("\n");

	status = DeviceIoControl(handle,
		TAP_CONTROL_CODE(10, 0), // TAP_IOCTL_CONFIG_TUN
		configtun,
		sizeof(configtun),
		configtun,
		sizeof(active),
		&len,
		NULL
		);

	if(status == 0)
	{
		printf("WARNING: The TAP-Windows driver rejected a TAP_IOCTL_CONFIG_TUN DeviceIoControl call.\n");
		return NULL;
	}
	printf("handle=%d\n", handle);
	return handle;
}

char g_strLocal[100];
char g_strRemote[100];
int g_nUdpSocket;

int openLocalUdp()
{

    // bind local port
    uint32 uListenIp = 0;
    uint16 uListenPort = 7002;
    parseIpPort(g_strLocal, &uListenIp, &uListenPort);

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = uListenIp;
    addr.sin_port = htons(uListenPort);
    socket_t nSocket = openUdp((sockaddr*)&addr, true);
    if (nSocket == INVALID_SOCKET) {
        printf("bind ip:%s   socket:%d  failed\n", inet_ntoa2(addr.sin_addr.s_addr), nSocket);
        return -1;
    }
    printf("bind ip:%s   socket:%d   ok.\n", inet_ntoa2(addr.sin_addr.s_addr), nSocket);
    g_nUdpSocket = nSocket;
    return 0;
}

#define MSG_BUFF_LEN 4096
class UdpSendThread : public ThreadBase
{
public:
    char _achData[MSG_BUFF_LEN];
    HANDLE _handle;
	OVERLAPPED _overlappedRx; 
public:
    int ThreadFunc();
};

int UdpSendThread::ThreadFunc()
{
    memset(&_overlappedRx, 0, sizeof(OVERLAPPED));
    uint32 uSvrIp = 0;
    uint16 uPort = 7006;
    parseIpPort(g_strRemote, &uSvrIp, &uPort);
    
    printf("---- Send to -> %s:%d\n", inet_ntoa2(uSvrIp), uPort);
 
    sockaddr_in addr2;
    addr2.sin_family = AF_INET;
    addr2.sin_addr.s_addr = uSvrIp;
    addr2.sin_port = htons(uPort);
    socklen_t nSockLen = sizeof(addr2);
	printf("handle=%d\n", _handle);
    while (1) {
        DWORD nLen;

		ResetEvent(_overlappedRx.hEvent);
		int ret = ReadFile(_handle,
					_achData,
					MSG_BUFF_LEN,
					&nLen, 
					&_overlappedRx
					);

        if (ret) //success
		{ 
            printf("read from tap success. nLen=%d\n", nLen);
        }
		else
		{
			DWORD err = GetLastError();
			if(err != ERROR_IO_PENDING)
			{
				printf("read from tap failed. err=%d\n", err);
				continue;
			}
			else
			{				 
				bool flag = false;
				while(!GetOverlappedResult(_handle, &_overlappedRx, &nLen, TRUE))
				{
					if(GetLastError() == ERROR_IO_INCOMPLETE)
					{
						printf("wait for read from tap...\n");
						continue;
					}
					else
					{
						printf("GetOverlappedResult failed. err=%d\n", GetLastError());
						flag = true;
					}
				}
				if(flag)
					continue;
				printf("read from tap success. nLen=%d\n", nLen);
			}
		}
        sys_printHex(_achData, nLen, "read data:\n");
        int nRet = sendto(g_nUdpSocket, _achData, nLen, 0, (sockaddr*)&addr2, nSockLen);
        printf(" ====> read:%d  send:%d\n", nLen, nRet);
    }
    return 0;
}

class UdpRecvThread : public ThreadBase
{
public:
    char _achData[MSG_BUFF_LEN];
    HANDLE _handle;
	OVERLAPPED _overlappedTx;
public:
    int ThreadFunc();
};

int UdpRecvThread::ThreadFunc()
{
	memset(&_overlappedTx, 0, sizeof(OVERLAPPED));

    while (1) {
        sockaddr_in addr2;
        memset(&addr2, 0, sizeof(addr2));
        addr2.sin_family = AF_INET;
        socklen_t nSockLen = sizeof(addr2);
        int nRet = recvfrom(g_nUdpSocket, _achData, MSG_BUFF_LEN, 0, 
                                (sockaddr*)&addr2, &nSockLen);
        if (nRet < 0) {
            printf("recvfrom failed.\n");
        }
		printf("nRet=%d\n", nRet);
        sys_printHex(_achData, nRet, "recv data:\n"); 
        DWORD nLen;
		int ret = WriteFile(_handle,
						_achData,
						nRet,
						&nLen,
						&_overlappedTx
						);
		
		//if (ret) //success
		//{ 
		//	printf("write to tap success. nLen=%d\n", nLen);
		//}
		if(!ret)
		{
			DWORD err = GetLastError();
			if(err != ERROR_IO_PENDING)
			{
				printf("write to tap failed. err=%d\n", err);
				continue;
			}
			else
			{
				printf("wait for write to tap...\n");
				WaitForSingleObject(_overlappedTx.hEvent, INFINITE);
				ret = GetOverlappedResult(_handle, &_overlappedTx, &nLen, FALSE);
				printf("write to tap. nLen=%d\n", nLen);
			}
		}

        printf(" <==== recv:%d  write:%d\n", nRet, nLen);
    }
    return 0;
}

UdpSendThread g_oUdpSend;
UdpRecvThread g_oUdpRecv;

int main(int argc, const char** argv)
{
	if (argc != 5) {
		printf("  %s <tap device's ip> <tap device's netmask> <local address> <remote address>\n", argv[0]);
		return 0;
	}
    
    strncpy_s(g_strLocal, argv[3], strlen(argv[3]));
    strncpy_s(g_strRemote, argv[4], strlen(argv[4]));

	char ip[100] = {0};
	char netmask[100] = {0};
	strncpy_s(ip, argv[1], strlen(argv[1]));
	strncpy_s(netmask, argv[2], strlen(argv[2]));
    
	if(initNet() < 0)
	{
		printf("init winsocks failed!\n");
		return 0;
	}

	HANDLE hTun = open_tun(ip, netmask);

    if (hTun == NULL) {
        return 0;
    }
    
    if (openLocalUdp() < 0) {
        return 0;
	}

    g_oUdpSend._handle = hTun;
    g_oUdpRecv._handle = hTun;
    g_oUdpSend.start();
    g_oUdpRecv.start();
    while (1) {
        sys_msleep(1000);
    }
	return 0;
}
