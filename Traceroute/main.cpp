#include "Traceroute.h"

int main() {

	WSADATA wsaData;

	//Initialize WinSock; once per program run
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return 0;
	}

	Traceroute tr = Traceroute();

	DWORD err;

	//if ((err = tr.trace("151.101.1.67")) != STATUS_OK) {
	if ((err = tr.trace("172.217.11.174")) != STATUS_OK) {
		printf("Error: %s\n",err);
	}
	//host_or_ip = "172.217.11.174"

	WSACleanup();

	return 0;
}