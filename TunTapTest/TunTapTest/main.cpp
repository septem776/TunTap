//#include <stdio.h>
//#include <windows.h>
//#include <winioctl.h>
//#include <iostream>
//#include <string>
//using namespace std;
//
//#define ADAPTER_KEY	"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
//#define TUNTAP_COMPONENT_ID "tap0901"
//
//#define TAP_CONTROL_CODE( request, method ) ( \
//	CTL_CODE( (FILE_DEVICE_UNKNOWN), (request), (method), 0) \
//)
//
//string get_tuntap_ComponentId()
//{
//	string ret;
//	long status;
//	HKEY hAdapterKey = NULL;
//	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ | KEY_WRITE, &hAdapterKey);
//	if(status != ERROR_SUCCESS)
//	{
//		printf("open key[%s] failed\n", ADAPTER_KEY);
//	}
//	int index = 0;
//	char buffer[256];
//	DWORD bufsize = sizeof(buffer);
//	HKEY hUnitKey = NULL;
//	while(RegEnumKeyEx(hAdapterKey, index, buffer, &bufsize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
//	{
//		status = RegOpenKeyEx(hAdapterKey, buffer, 0, KEY_READ | KEY_WRITE, &hUnitKey);
//		if(status != ERROR_SUCCESS)
//		{
//			printf("open key[%s] failed\n", buffer);
//			index++;
//			memset(buffer, 0, sizeof(buffer));
//			bufsize = sizeof(buffer);
//			continue;
//		}
//		char component_id[256] = {0};
//		DWORD len = sizeof(component_id);
//		DWORD dType;
//		status = RegQueryValueEx(hUnitKey, "ComponentId", 0, &dType, (LPBYTE)component_id, &len);
//		if(strncmp(component_id, TUNTAP_COMPONENT_ID, len) == 0) // found tun device
//		{
//			char instance_id[256];
//			DWORD ins_len = sizeof(instance_id);
//			status = RegQueryValueEx(hUnitKey, "NetCfgInstanceId", 0, &dType, (LPBYTE)instance_id, &ins_len);
//			printf("tun device found, instance id=%s\n", instance_id);
//			ret = instance_id;
//			break;
//		}
//
//		index++;
//		memset(buffer, 0, sizeof(buffer));
//		bufsize = sizeof(buffer);
//	}
//	return ret;
//}
//
//int main()
//{
//	string component_id = get_tuntap_ComponentId();
//	char device_path[256] = {0};
//	sprintf_s(device_path, sizeof(device_path), "\\\\.\\%s.tap", component_id.c_str());
//	HANDLE handle = CreateFile(	device_path,
//								GENERIC_READ | GENERIC_WRITE,
//								FILE_SHARE_READ | FILE_SHARE_WRITE,
//								NULL,
//								OPEN_EXISTING,
//								FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
//								NULL);
//	if(handle == INVALID_HANDLE_VALUE)
//	{
//		printf("CreateFile failed on TAP device: %s\n", device_path);
//	}
//	DWORD active = 1;
//	DWORD len;
//	int status = DeviceIoControl(handle, 
//					TAP_CONTROL_CODE(6, 0),	// TAP_IOCTL_SET_MEDIA_STATUS
//					&active,
//					sizeof(active),
//					&active,
//					sizeof(active),
//					&len,
//					NULL
//					);
//	if(status == 0)
//	{
//		printf("WARNING: The TAP-Windows driver rejected a TAP_WIN_IOCTL_SET_MEDIA_STATUS DeviceIoControl call.\n");
//		return -1;
//	}
//
//	int configtun[3] = {0x0100020a, 0x0000020a, 0x0000ffff};
//	status = DeviceIoControl(handle,
//				TAP_CONTROL_CODE(10, 0), // TAP_IOCTL_CONFIG_TUN
//				configtun,
//				sizeof(configtun),
//				configtun,
//				sizeof(active),
//				&len,
//				NULL
//				);
//
//	if(status == 0)
//	{
//		printf("WARNING: The TAP-Windows driver rejected a TAP_IOCTL_CONFIG_TUN DeviceIoControl call.\n");
//		return -1;
//	}
//
//	while(1)
//	{
//		Sleep(1000);
//	}
//
//	return 0;
//}