#pragma once
#include "Checksum.h"

/*
* Taken from Stack Overflow question 1739259
* http://stackoverflow.com/questions/1739259/how-to-use-queryperformancecounter
* Answer by Ramonster
* With modifications
*/

class PreciseCounter {

private:
	double PCFreq;
	__int64 CounterStart;

public:
	PreciseCounter() {
		double PCFreq = 0.0;
		__int64 CounterStart = 0;
	}

	void startCounter(){
		LARGE_INTEGER li;
		if (!QueryPerformanceFrequency(&li)) {
			printf("QueryPerformanceFrequency failed!\n");
		}

		PCFreq = double(li.QuadPart) / 1000.0;

		QueryPerformanceCounter(&li);
		CounterStart = li.QuadPart;
	}

	double getCounter(){
		LARGE_INTEGER li;
		QueryPerformanceCounter(&li);
		return double(li.QuadPart - CounterStart) / PCFreq;
	}
};
