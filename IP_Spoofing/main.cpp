#include<tins/tins.h>
#include<iostream>
#include<WinSock2.h>
#define HAVE_REMOTE
#define WPCAP
#include<string>
#include<IPHlpApi.h>

using namespace std;
using namespace Tins;

#pragma comment(lib, "ws2_32.lib")		//winsock2
#pragma comment(lib, "iphlpapi.lib")	//get mac

void init() {
#ifdef _WIN32_
	WSADATA wsaData;
	WSAStartup(0x0202, &wsaData);
#endif // _WIN32_
}

int main() {

	return 0;
}