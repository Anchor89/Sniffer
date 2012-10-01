/*
 * main.cpp
 *
 *  Created on: 2012-9-26
 *      Author: Anchor
 */

// C++ Library
#include <iostream>
#include <string>

// WinPcap SDK
#include "pcap.h"

#include <winsock2.h>

#include "interface.h"
#include "PacketHandler.h"

using namespace std;
using ucas_sniffer::Interface;
using ucas_sniffer::PacketHandler;

void output_err_buf(char* err_buf, char* fun);

void packet_handler_show(unsigned char* param, const pcap_pkthdr* header, const unsigned char* pkt_data);

int trysth();
int testpcap();
int dump();
int cap();
int cap_file();

int main() {
//  return trysth();
//  return testpcap();
//  return dump();
//  return cap();
  return cap_file();
}

int trysth() {
  in_addr ina;
  in_addr inb;
  inb.S_un.S_un_b.s_b1 = 0x11;
  inb.S_un.S_un_b.s_b2 = 0x22;
  inb.S_un.S_un_b.s_b3 = 0x33;
  inb.S_un.S_un_b.s_b4 = 0x44;
  unsigned int a = 0x11223344;

  cout << inb.S_un.S_addr << endl;
  cout << inet_ntoa(inb) << endl;
  cout << a << endl;
  ina.S_un.S_addr = a;
  cout << inet_ntoa(ina);
  return 0;
}

int testpcap() {
  pcap_if_t* all_devs;
  pcap_if_t* cur;
  char* err_buf = new char[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs_ex("rpcap://", NULL, &all_devs, err_buf) == -1) {
    output_err_buf(err_buf, "pcap_findalldevs_ex");
    exit(1);
  }

  vector<ucas_sniffer::Interface> interfaces;
  for (cur = all_devs; cur != NULL; cur = cur->next) {
    interfaces.push_back(ucas_sniffer::Interface(cur));
    (interfaces.end() - 1)->Show();
    cout << endl;
  }

  pcap_freealldevs(all_devs);

  cout << "END" << endl;

  return 0;
}

void output_err_buf(char* err_buf, char* fun) {
  cerr << "Error in " << fun << ":" << err_buf << endl;
}

void packet_handler_dump(unsigned char *param, const struct pcap_pkthdr *header,
    const unsigned char *pkt_data);

int dump() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int inum;
  int i = 0;
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_dumper_t *dumpfile;

  cout << "Begin:" << endl;

  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
    output_err_buf(errbuf, "pcap_findalldevs");
    exit(1);
  }

  cout << "Found" << endl;

  for (d = alldevs; d != NULL; d = d->next) {
    cout << "Name " << ++i << ":" << d->name << endl;
    if (d->description)
      cout << "Description: " << d->description;
    else
      cout << "No description available" << endl;
  }

  if (i == 0) {
    cout << "No interfaces found! Make sure WinPcap is installed." << endl;
    return -1;
  }

  cout << "Enter the interface number (1-" << i << "):" << endl;
  cin >> inum;

  if (inum < 1 || inum > i) {
    cout << "\nInterface number out of range." << endl;
    pcap_freealldevs(alldevs);
    return -1;
  }

  for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
    ;

  if ((adhandle = pcap_open(d->name,
      65536,
      PCAP_OPENFLAG_PROMISCUOUS,
      1000,
      NULL,
      errbuf
      )) == NULL) {
    cerr << "Unable to open the adapter. " << d->name << " is not supported by WinPcap\n";

    pcap_freealldevs(alldevs);
    return -1;
  }

  dumpfile = pcap_dump_open(adhandle, "end.pcap");

  if (dumpfile == NULL) {
    cerr << "Error opening output file\n";
    return -1;
  }

  cout << "listening on " << d->description << "... Press Ctrl+C to stop...\n";

  pcap_freealldevs(alldevs);

  pcap_loop(adhandle, 0, packet_handler_dump, (unsigned char *) dumpfile);

  return 0;
}

void packet_handler_dump(unsigned char *dumpfile, const struct pcap_pkthdr *header,
    const unsigned char *pkt_data) {
  /* 保存数据包到堆文件 */
  static int count = 0;
  count++;
  cout << "Packet count: " << count << endl;
  pcap_dump(dumpfile, header, pkt_data);
}

int cap() {

  pcap_if_t* dev_list;
  pcap_if_t* cur;
  pcap_t* cap_handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  vector<Interface> interfaces;

  if (pcap_findalldevs_ex("rpcap://", NULL, &dev_list, errbuf) == -1) {
    output_err_buf(errbuf, "pcap_findalldev_ex()");
    exit(1);
  }

  for (cur = dev_list; cur != NULL; cur = cur->next) {
    interfaces.push_back(Interface(cur));
  }

  pcap_freealldevs(dev_list);

  vector<Interface>::iterator ite;
  for (ite = interfaces.begin(); ite != interfaces.end(); ++ite) {
    if (ite->HasValidAddress()) {
      ite->Capture(packet_handler_show, 0, NULL);
    }
  }


  return 0;
}

int cap_file() {

  Interface::CaptureFromFile("f:\\MyProjects\\Sniffer\\test.pcap", packet_handler_show, NULL);

  cout << "END" << endl;

  return 0;
}

void packet_handler_show(unsigned char* param, const pcap_pkthdr* header, const unsigned char* pkt_data) {
  static int count = 0;
  cout << "Packet " << ++count;
  cout << "===================================================" << endl;
  PacketHandler ph;
  ph.PointTo(pkt_data, header->caplen);
  ph.Parse();
  ph.Show();
  cout << endl;
}
