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
#define MAX_HOPS 30

class Traceroute {
public:
	Traceroute();
	DWORD trace(char *host_or_ip);
private:
	DWORD startThreads();

	ICMPResponseInfo *info_arr[MAX_HOPS];

	HANDLE handles[MAX_HOPS];
	ThreadData *thread_data_arr[MAX_HOPS];

	SOCKET sock;

	socklen_t sin_size;
	struct sockaddr_in sin;

	u_short id;

	DWORD initializeSocket();

	DWORD sendICMPPacket(DWORD IP, int ttl);

	DWORD sendFirstWaveOfPackets(DWORD IP);
	DWORD recvICMPPackets();

	DWORD handleRetx();

	DWORD dnsLookUp(u_long source_ip, u_short seq);

	DWORD closeAllThreads(); //Closes all the threads that are still open

	void retrieveHostNames();

	void printResults();

};