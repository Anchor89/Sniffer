/*
 * UdpParser.cpp
 *
 *  Created on: 2012-10-1
 *      Author: Anchor
 */

#include "UdpParser.h"

namespace ucas_sniffer {

UdpParser::UdpParser() : ProtocolParserBase("UDP") {
  Clear();
}

UdpParser::~UdpParser() {
  // Nothing to do
}

bool UdpParser::Parse(const unsigned char* head, const unsigned int len) {
  if (head == NULL || len == 0) {
    return false;
  }

  source_port_ = PE::ParseBuf(head, PE::UDP_SOURCE_PORT_OFFSET, PE::UDP_SOURCE_PORT_BITLEN);
  destination_port_ = PE::ParseBuf(head, PE::UDP_DESTINATION_PORT_OFFSET, PE::UDP_DESTINATION_PORT_BITLEN);
  length_ = PE::ParseBuf(head, PE::UDP_LENGTH_OFFSET, PE::UDP_LENGTH_BITLEN);
  checksum_ = PE::ParseBuf(head, PE::UDP_CHECKSUM_OFFSET, PE::UDP_CHECKSUM_BITLEN);

  header_ = head;
  header_length_ = 8;
  body_ = header_ + header_length_;
  body_length_ = length_ - 8;

  return true;
}

void UdpParser::Clear() {
  header_ = NULL;
  header_length_ = 0;
  body_ = NULL;
  body_length_ = 0;

  source_port_ = 0;
  destination_port_ = 0;
  checksum_ = 0;
}

void UdpParser::Show() const {
  cout << protocol_name_ << endl;
  cout << "Header length: " << header_length_ << endl;
  cout << "Body length: " << body_length_ << endl;
  cout << "Source port: " << source_port_ << endl;
  cout << "Destination port: " << destination_port_ << endl;
  cout << "Length: " << length_ << endl;
  cout << "Checksum: " << checksum_ << endl;
}
} /* namespace ucas_sniffer */
