#pragma once
#include "ICMPResponseInfo.h"

//Return values for Traceroute
#define STATUS_OK 0
#define SOCKET_CREATE_FAILED 1
#define SEND_FAILED 2
#define INVALID_NAME 3
#define FAILED_SEND 4
#define FAILED_RECV 5

//Constant Values
#define MAX_PROBES 3
#define INTIAL_PROBE_TIMEOUT 500

class Traceroute {
public:
	Traceroute();
	DWORD trace(char *host_or_ip);
private:
	const int info_arr_size = 30;
	ICMPResponseInfo *info_arr[info_arr_size];

	SOCKET sock;

	socklen_t sin_size;
	struct sockaddr_in sin;

	u_short id;

	DWORD initializeSocket();

	DWORD sendICMPPacket(DWORD IP, int ttl);
	DWORD recvICMPPacket();

	DWORD dnsLookUp(u_long source_ip);

};