#pragma once
#include "DNSThreading.h"

class ICMPResponseInfo {
public:
	ICMPResponseInfo() {
		number_of_attempts = 0;
		ip = NULL;
		host_name = "";
		time_sent = 0;
		RTT = 0;
		RTO = 0;
		success = false;
		final_destination = false;
		unexpected_code = false;
		error_message = "";
	}

	int number_of_attempts;
	u_long ip;
	std::string host_name;
	double time_sent;
	double RTT;
	int RTO;
	boolean success; //Did it succeed?
	boolean final_destination; //Is this the final destination?
	
	boolean unexpected_code; //Was an unexpected code returned?
	std::string error_message;
};