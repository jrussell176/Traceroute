#pragma once
#include "ICMPResponseInfo.h"

//Return values for Traceroute
#define STATUS_OK 0
#define SOCKET_CREATE_FAILED 1
#define SEND_FAILED 2
#define INVALID_NAME 3
#define FAILED_SEND 4
#define FAILED_RECV 5
#define FAILED_DNS_LOOKUP 6

//Constant Values
#define MAX_PROBES 3
#define INITIAL_PROBE_TIMEOUT 500
#define MAX_HOPS 30

class Traceroute {
public:
	Traceroute();
	DWORD trace(char *host_or_ip);
	DWORD traceBatchMode(std::vector<char*> vec);
private:
	DWORD startThreads();

	ICMPResponseInfo *info_arr[MAX_HOPS];

	HANDLE handles[MAX_HOPS];
	ThreadData *thread_data_arr[MAX_HOPS];

	SOCKET sock;
	fd_set fd;

	socklen_t sin_size;
	struct sockaddr_in sin;

	PreciseCounter pc;

	u_short id;

	//Statisics for report
	int hop_counts[MAX_HOPS];
	std::set<u_long> unique_ips;
	int total_number_of_ips;
	int longest_trace;
	DWORD ip_for_longest_trace;
	int trace_times[40];
	std::vector<double> trace_times_vec;
	
	void initializeInfoArr();

	DWORD initializeSocket();

	DWORD sendICMPPacket(DWORD IP, int ttl);

	DWORD sendFirstWaveOfPackets(DWORD IP);
	DWORD recvICMPPackets(bool batchMode);

	DWORD calculateRTO(std::stack<int> stk);

	DWORD handleRetx(DWORD IP, bool batchMode);

	DWORD dnsLookUp(u_long source_ip, u_short seq);

	DWORD closeAllThreads(); //Closes all the threads that are still open

	void retrieveHostNames();

	void printResults();

	bool gatherStatisticsAboutTrace();

	void printStatistics();

};