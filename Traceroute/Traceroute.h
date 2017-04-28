#pragma once
#include "NetworkStructs.h"

//Return values for Traceroute
#define STATUS_OK 0

//Constant Values
#define MAX_PROBES 3
#define INTIAL_PROBE_TIMEOUT 500

class Traceroute {
public:
	DWORD trace(char *host_or_ip);
private:
	Traceroute();

	DWORD createICMPPacket();

};