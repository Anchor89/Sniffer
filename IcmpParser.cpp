/*
 * IcmpParser.cpp
 *
 *  Created on: 2012-10-1
 *      Author: Anchor
 */

#include <iostream>

#include "IcmpParser.h"

using std::cout;
using std::endl;
using std::cerr;
using std::hex;
using std::dec;

namespace ucas_sniffer {

IcmpParser::IcmpParser() : ProtocolParserBase("ICMP"){
  Clear();
}

IcmpParser::~IcmpParser() {
  // Nothing to do
}

bool IcmpParser::Parse(const unsigned char* head, const unsigned int len) {
  if (head == NULL || len == 0) {
    return false;
  }

  header_ = head;
  header_length_ = len;
  body_ = NULL;
  body_length_ = 0;

  type_ = PE::ParseBuf(head, PE::ICMP_TYPE_OFFSET, PE::ICMP_TYPE_BITLEN);
  code_ = PE::ParseBuf(head, PE::ICMP_CODE_OFFSET, PE::ICMP_CODE_BITLEN);
  checksum_ = PE::ParseBuf(head, PE::ICMP_CHECKSUM_OFFSET, PE::ICMP_CHECKSUM_BITLEN);

  return true;
}

void IcmpParser::Clear() {
  header_ = NULL;
  header_length_ = 0;
  body_ = NULL;
  body_length_ = 0;

  type_ = 0;
  code_ = 0;
  checksum_ = 0;
}

void IcmpParser::Show() const {
  cout << protocol_name_ << endl;
  cout << "Header length: " << header_length_ << endl;
  cout << "Body  length: " << body_length_ << endl;
  cout << "Type: " << type_ << endl;
  cout << "Code: " << code_ << endl;
  cout << "Checksum: " << hex << checksum_ << dec << endl;
  if (header_length_ > 4 ) {
    cout << "Rest header length: " << header_length_ - 4 << " bytes" << endl;
    cout << "Rest data: 0x" << hex;
    for (int i = 4; i < header_length_; i++) {
      cout.widen(2);
      cout.fill('0');
      cout << (unsigned short)(header_[i]) << " ";
    }
  }
}

} /* namespace ucas_sniffer */
