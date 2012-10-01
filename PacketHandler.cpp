/*
 * PacketHandler.cpp
 *
 *  Created on: 2012-9-28
 *      Author: Anchor
 */

#include <iostream>

#include "PacketHandler.h"

using std::cout;
using std::cerr;
using std::endl;

namespace ucas_sniffer {

PacketHandler::PacketHandler() {
  data_ = NULL;
  size_ = 0;
  is_the_owner_ = false;
  parser_stack_.clear();
  mac_parser_.reset(new MacParser);
  arp_parser_.reset(new ArpParser);
  ipv4_parser_.reset(new Ipv4Parser);
  icmp_parser_.reset(new IcmpParser);
  igmp_parser_.reset(new IgmpParser);
  tcp_parser_.reset(new TcpParser);
  udp_parser_.reset(new UdpParser);
}

PacketHandler::~PacketHandler() {
  if (is_the_owner_) {
    delete data_;
  }
}

void PacketHandler::PointTo(const unsigned char* data, const unsigned int size) {
  data_ = data;
  size_ = size;
  is_the_owner_ = false;
}

void PacketHandler::MakeCopy(const unsigned char* data, const unsigned int size) {
  unsigned char* buf = new unsigned char[size];
  memcpy(buf, data, size);
  data_ = buf;
  size_ = size;
  is_the_owner_ = true;
}

void PacketHandler::Parse() {
  if ( data_ == NULL ) {
    return ;
  }

  if (mac_parser_->Parse(data_, size_)) {
    parser_stack_.push_back(mac_parser_.get());
  }
  else {
    cerr << "MAC Parse failed" << endl;
  }


  if (mac_parser_->type() == PE::MAC_TYPE_ARP) {
    // Payload is ARP
    arp_parser_->Parse(mac_parser_->body(), mac_parser_->body_length());
    parser_stack_.push_back(arp_parser_.get());
  }
  else if (mac_parser_->type() == PE::MAC_TYPE_IP) {
    // Payload is IPv4
    ipv4_parser_->Parse(mac_parser_->body(), mac_parser_->body_length());
    parser_stack_.push_back(ipv4_parser_.get());
    if (ipv4_parser_->protocol() == PE::IP_PROTOCOL_ICMP) {
      // Payload is ICMP
      icmp_parser_->Parse(ipv4_parser_->body(), ipv4_parser_->body_length());
      parser_stack_.push_back(icmp_parser_.get());
    }
    else if (ipv4_parser_->protocol() == PE::IP_PROTOCOL_IGMP) {
      // Payload is IGMP
      igmp_parser_->Parse(ipv4_parser_->body(), ipv4_parser_->body_length());
      parser_stack_.push_back(igmp_parser_.get());
    }
    else if (ipv4_parser_->protocol() == PE::IP_PROTOCOL_TCP) {
      // Payload is TCP
      tcp_parser_->Parse(ipv4_parser_->body(), ipv4_parser_->body_length());
      parser_stack_.push_back(tcp_parser_.get());
    }
    else if (ipv4_parser_->protocol() == PE::IP_PROTOCOL_UDP) {
      // Payload is UDP
      udp_parser_->Parse(ipv4_parser_->body(), ipv4_parser_->body_length());
      parser_stack_.push_back(udp_parser_.get());
    }
    else {
      // Payload is unknown
      cerr << "Payload of IPv4 is unknown" << endl;
    }
  }
  else if (mac_parser_->type() == PE::MAC_TYPE_RARP) {
    // Payload is RARP
    // TODO: RARP is not required.
  }
  else {
    // Payload is Unknown
    cerr << "Payload of MAC is unknown" << endl;
  }
}

void PacketHandler::Show() const {
  if (parser_stack_.empty()) {
    cout << "Can not be parsed" << endl;
    return ;
  }

  int size = parser_stack_.size();
  cout << "Packet length: " << size_ << endl;
  for (int i=0; i<size; i++) {
    parser_stack_.at(i)->Show();
    cout << endl;
  }
}

void PacketHandler::Clear() {
  if (is_the_owner_) {
    delete data_;
    is_the_owner_ = false;
  }
  data_ = NULL;
  size_ = 0;
}
} /* namespace ucas_sniffer */
