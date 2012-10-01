/*
 * Ipv4Parser.cpp
 *
 *  Created on: 2012-9-28
 *      Author: Anchor
 */

#include <iostream>
#include <bitset>

#include "Ipv4Parser.h"

using std::cout;
using std::cerr;
using std::endl;
using std::hex;
using std::dec;
using std::bitset;

namespace ucas_sniffer {

Ipv4Parser::Ipv4Parser() : ProtocolParserBase("IPv4") {
  Clear();
}

Ipv4Parser::~Ipv4Parser() {
  // Nothing
}

bool Ipv4Parser::Parse(const unsigned char* head, const unsigned int len) {
  if (head == NULL || len == 0 ) {
    return false;
  }

  version_ = PE::ParseBuf(head, PE::IP_VERSION_OFFSET, PE::IP_VERSION_BITLEN);
  header_length_ = PE::ParseBuf(head, PE::IP_HEADER_LENGTH_OFFSET, PE::IP_HEADER_LENGTH_BITLEN) << 2;
  tos_ = PE::ParseBuf(head, PE::IP_TOS_OFFSET, PE::IP_TOS_BITLEN);
  total_length_ = PE::ParseBuf(head, PE::IP_TOTAL_LENGTH_OFFSET, PE::IP_TOTAL_LENGTH_BITLEN);
  id_ = PE::ParseBuf(head, PE::IP_ID_OFFSET, PE::IP_ID_BITLEN);
  flags_ = PE::ParseBuf(head, PE::IP_FLAG_OFFSET, PE::IP_FLAG_BITLEN);
  fragment_offset_ = PE::ParseBuf(head, PE::IP_FRAGMENT_OFFSET_OFFSET, PE::IP_FRAGMENT_OFFSET_BITLEN);
  ttl_ = PE::ParseBuf(head, PE::IP_TTL_OFFSET, PE::IP_TTL_BITLEN);
  protocol_ = PE::ParseBuf(head, PE::IP_PROTOCOL_OFFSET, PE::IP_PROTOCOL_BITLEN);
  header_checksum_ = PE::ParseBuf(head, PE::IP_CHECKSUM_OFFSET, PE::IP_CHECKSUM_BITLEN);
  source_ip_.set_addr(PE::ParseBuf(head, PE::IP_SOURCE_ADDRESS_OFFSET, PE::IP_SOURCE_ADDRESS_BITLEN));
  destination_ip_.set_addr(PE::ParseBuf(head, PE::IP_DESTINATION_ADDRESS_OFFSET, PE::IP_DESTINATION_ADDRESS_BITLEN));

  header_ = head;
  if (header_length_ <= len) {
    body_ = header_ + header_length_;
    body_length_ = len - header_length_;
  }
  else {
    body_ = NULL;
    body_length_ = 0;
  }

  return true;
}

void Ipv4Parser::Clear() {
  header_ = NULL;
  body_ = NULL;
  header_length_ = 0;
  body_length_ = 0;
  version_ = 0;
  tos_ = 0;
  total_length_ = 0;
  id_ = 0;
  flags_ = 0;
  fragment_offset_ = 0;
  ttl_ = 0;
  protocol_ = 0;
  header_checksum_ = 0;
  source_ip_ = 0;
  destination_ip_ = 0;
}

void Ipv4Parser::Show() const {
  cout << protocol_name_ << endl;
  cout << "Header's length is: " << header_length_ << endl;
  cout << "Body's length is:" << body_length_ << endl;
  cout << "Version: " << version_ << endl;
  cout << "Type of service: " << bitset<3>(tos_) << endl;
  cout << "Total length: " << total_length_ << endl;
  cout << "ID: " << id_ << endl;
  cout << "Flags: " << bitset<3>(flags_) << endl;
  cout << "Fragment offset: " << fragment_offset_ << endl;
  cout << "TTL: " << ttl_ << endl;
  cout << "Protocol Number: " << protocol_ << "  Name: ";
  switch(protocol_) {
    case 1: // PE::IP_PROTOCOL_ICMP
      cout << "ICMP" << endl;
      break;
    case 2: // PE::IP_PROTOCOL_IGMP
      cout << "IGMP" << endl;
      break;
    case 4: // PE::IP_PROTOCOL_IPV4
      cout << "IPv4" << endl;
      break;
    case 6: // PE::IP_PROTOCOL_TCP
      cout << "TCP" << endl;
      break;
    case 17: // PE::IP_PROTOCOL_UDP
      cout << "UDP" << endl;
      break;
    default:
      cout << "Unknown" << endl;
      break;
  }
  cout << "Header checksum: " << header_checksum_ << endl;
  cout << "Source IP: " << source_ip_.ToString() << endl;
  cout << "Destination IP: " << destination_ip_.ToString() << endl;
}

} /* namespace ucas_sniffer */
