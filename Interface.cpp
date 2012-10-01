/*
 * Interface.cpp
 *
 *  Created on: 2012-9-26
 *      Author: Anchor
 */



#include "Interface.h"

namespace ucas_sniffer
{
  Interface::Interface()
  {
    has_valid_addr_ = false;
    is_loopback_ = false;
  }

  Interface::~Interface()
  {
  }

  bool Interface::ParseFrom(const pcap_if_t* dev) {
    if (dev == NULL) {
      return false;
    }

    name_ = dev->name == NULL? "" : dev->name;
    description_ = dev->description == NULL? "": dev->description;
    is_loopback_ = (dev->flags & PCAP_IF_LOOPBACK) == PCAP_IF_LOOPBACK;
    addresses_.clear();
    for (pcap_addr* cur = dev->addresses; cur != NULL; cur = cur->next) {
      if (cur->addr->sa_family == AF_INET) {
        addresses_.push_back(IfAddress(cur));
        has_valid_addr_ = ( has_valid_addr_ || addresses_.end()->IsValid() );
      }
    }
    return true;
  }

  bool Interface::ParseFrom(const pcap_if_t& dev) {
    return ParseFrom(&dev);
  }

  int Interface::Capture(pcap_handler handler, int count, unsigned char* user) {
    if (!has_valid_addr_) {
      return -3;
    }

    auto_ptr<char> errbuf;
    errbuf.reset(new char[PCAP_ERRBUF_SIZE]);
    pcap_t* opened = pcap_open(name_.c_str(), 65535,
        PCAP_OPENFLAG_PROMISCUOUS,
        1000, NULL, errbuf.get());
    return pcap_loop(opened, count, handler, user);
  }

  int Interface::CaptureTimeout(pcap_handler handler, int timeout, int count, unsigned char* user) {
    if (!has_valid_addr_) {
      return -3;
    }

    auto_ptr<char> errbuf;
    errbuf.reset(new char[PCAP_ERRBUF_SIZE]);
    pcap_t* opened = pcap_open(name_.c_str(), 65535,
        PCAP_OPENFLAG_PROMISCUOUS,
        timeout, NULL, errbuf.get());
    return pcap_dispatch(opened, count, handler, user);
  }

  int Interface::CaptureFromFile(const string& filename, pcap_handler handler, unsigned char* user) {
    pcap_t* file;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];

    if (pcap_createsrcstr(source,
                          PCAP_SRC_FILE,
                          NULL,
                          NULL,
                          filename.c_str(),
                          errbuf) != NULL) {
      cout << "Error in pcap_createsrcstr(): " << errbuf << endl;
      return -3;
    }

    if ((file = pcap_open(source, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
      cout << "Error in pcap_open(): " << errbuf << endl;
      return -3;
    }


    cout << "Begin to read file" << endl;

    pcap_loop(file, 0, handler, user);

    return 0;
  }

  void Interface::Show() {
    cout << "Name: " << name_ << endl;
    cout << "Description: " << description_ << endl;
    cout << "Has " << (is_loopback_? "":"No ") << "Loopback" << endl;
    for (int i = 0; i < addresses_.size(); i++) {
      addresses_.at(i).Show();
    }
  }
} /* namespace ucas_sniffer */
