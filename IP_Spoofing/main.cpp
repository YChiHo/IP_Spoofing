#define TINS_STATIC
#include<iostream>
#include<tins/tins.h>
#include<tins/ethernetII.h>
#include<WinSock2.h>
#include<pcap.h>
#include<IPHlpApi.h>

using std::cout;
using std::runtime_error;
using std::endl;
using namespace Tins;

#pragma comment(lib, "ws2_32.lib")		//winsock2
#pragma comment(lib, "wpcap.lib")		//winpcap
#pragma comment(lib, "iphlpapi.lib")	//get mac
#pragma comment(lib, "tins.lib")

void init() {
#ifdef _WIN32_
	WSADATA wsaData;
	WSAStartup(0x0202, &wsaData);
#endif // _WIN32_
}

void do_ip_spoofing(NetworkInterface iface, IPv4Address target, IPv4Address gateway, const NetworkInterface::Info& info) {

}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		cout << "ips <Target> <Gateway>" << endl;
		return -1;
	}

	PacketSender sender;

	IPv4Address target_ip = IPv4Address(argv[2]);
	return 0;
}
