/*
 * MacParser.cpp
 *
 *  Created on: 2012-9-27
 *      Author: Anchor
 */

// C++ Standard Library
#include <iostream>

#include "MacParser.h"
#include "ProtocolEnumerate.h"
#include "util.h"

using namespace std;

namespace ucas_sniffer {

const unsigned int MacParser::MAC_FRAME_MIN_LEN = 40;

MacParser::MacParser() : ProtocolParserBase("MAC") {
  type_ = 0;
}

MacParser::~MacParser() {
  // Nothing to do here
}

bool MacParser::Parse(const unsigned char* head, const unsigned int len) {
  if (head == NULL || len < MAC_FRAME_MIN_LEN) {
    return false;
  }

  header_ = head;
  header_length_ = PE::MAC_HEADER_LENGTH >> 3;
  if (len > header_length_) {
    body_length_ = len - header_length_;
    body_ = header_ + header_length_;
  }
  else {
    body_length_ = 0;
    body_ = NULL;
  }

  dst_addr_.set_addr(head + (PE::MAC_DST_ADDR_OFFSET >> 3));
  src_addr_.set_addr(head + (PE::MAC_SRC_ADDR_OFFSET >> 3));
  type_ = PE::ParseBuf(head, PE::MAC_TYPE_OFFSET, PE::MAC_TYPE_BITLEN);

  return true;
}

void MacParser::Clear() {
  header_length_ = 0;
  body_length_ = 0;
  header_ = NULL;
  body_ = NULL;
  dst_addr_.set_addr(NULL);
  src_addr_.set_addr(NULL);
  type_ = 0;
}

void MacParser::Show() const {
  cout << protocol_name_ << endl;
  cout << "Header's length is: " << header_length_ << endl;
  cout << "Body's length is: " << body_length_ << endl;
  cout << "Destination address is: " << dst_addr_.ToString() << endl;
  cout << "Source address is: " << src_addr_.ToString() << endl;
  switch(type_) {
    case 0x0800: // PE::MAC_TYPE_IP
      cout << "Payload's Type is: IP" << endl;
      break;
    case 0x0806: // PE::MAC_TYPE_ARP
      cout << "Payload's Type is: ARP" << endl;
      break;
    case 0x8035: // PE::MAC_TYPE_RARP
      cout << "Payload's Type is: RARP" << endl;
      break;
    default:
      cout << "Payload's Type is: UNKNOWN" << endl;
      break;
  }
}

} /* namespace ucas_sniffer */
