#include "Traceroute.h"

int main(int argc, char* argv[]){

	if (argc != 2) {
		std::cout << "Please a host or ip to trace to\n" << std::endl;
		return 0;
	}

	char *host_or_ip = argv[1];


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

	if ((err = tr.trace(host_or_ip)) != STATUS_OK) {
		printf("Error: %s\n", err);
	}

	/*
	std::string fileName = "1M-hosts.txt";

	std::string line;
	std::ifstream urlFile("1M-hosts.txt");
	std::vector<char *> urlVec;

	std::ifstream in(fileName.c_str(), std::ifstream::ate | std::ifstream::binary);

	if (urlFile.is_open())
	{
		//std::cout << "Opened " << fileName << " with size " << in.tellg() << " bytes\n" << std::endl;
		int i = 0;
		while (getline(urlFile, line))
		{
			//i++;
			//printf("%d\n", i);
			urlVec.push_back(strdup(line.c_str()));
		}
		urlFile.close();
	}
	else {
		std::cout << "Unable to open file";
	}
	*/
	//printf("Vec Size: %d\n", urlVec.size());
	

	//Regular trace
	/*
	//if ((err = tr.trace("1.1.1.1")) != STATUS_OK) {
	//if ((err = tr.trace("172.217.11.174")) != STATUS_OK) {
	//if ((err = tr.trace("article.wn.com")) != STATUS_OK) {
	//if ((err = tr.trace("212.58.246.227")) != STATUS_OK) {
	if ((err = tr.trace("yahoo.com")) != STATUS_OK) {
		printf("Error: %s\n",err);
	}
	//host_or_ip = "172.217.11.174"
	*/

	//Batch Mode
	/*
	std::vector<char *> vec;
	vec.push_back("151.101.1.67");
	vec.push_back("172.217.11.174");
	vec.push_back("212.58.246.227");
	vec.push_back("165.91.22.70");
	vec.push_back("www.yahoo.com");
	vec.push_back("www.google.com");
	vec.push_back("1.1.1.1");
	if ((err = tr.traceBatchMode(vec)) != STATUS_OK) {
		//if ((err = tr.trace("172.217.11.174")) != STATUS_OK) {
		//if ((err = tr.trace("212.58.246.227")) != STATUS_OK) {
		printf("Error: %s\n", err);
	}
	*/
	//host_or_ip = "172.217.11.174"
	

	//Batch File mode
	
	/*
	if ((err = tr.traceBatchMode(urlVec)) != STATUS_OK) {
		//if ((err = tr.trace("172.217.11.174")) != STATUS_OK) {
		//if ((err = tr.trace("212.58.246.227")) != STATUS_OK) {
		printf("Error: %s\n", err);
	}
	*/
	
	

	
	
	WSACleanup();

	return 0;
}