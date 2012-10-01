/*
 * ArpParser.cpp
 *
 *  Created on: 2012-9-27
 *      Author: Anchor
 */

#include <iostream>

#include "util.h"
#include "ArpParser.h"

using namespace std;

namespace ucas_sniffer {

const unsigned int ArpParser::ARP_MIN_LEN = 28;

ArpParser::ArpParser() : ProtocolParserBase("ARP") {
  Clear();
}

ArpParser::~ArpParser() {
  // Nothing to do here
}

bool ArpParser::Parse(const unsigned char* head, const unsigned int len) {
  if (head == NULL || len <= ARP_MIN_LEN) {
    return false;
  }

  header_length_ = len;
  body_length_ = 0;
  header_ = head;
  body_ = NULL;

  hardware_type_ = Assemble(head[0], head[1]);
  protocol_type_ = Assemble(head[2], head[3]);
  hardware_len_ = head[4];
  protocol_len_ = head[5];
  op_ = Assemble(head[6], head[7]);
  sender_mac_.set_addr(head + 8);
  sender_ip_.set_addr(AssembleUint32(head + 14));
  recver_mac_.set_addr(head + 18);
  recver_ip_.set_addr(AssembleUint32(head + 24));

  return true;
}

void ArpParser::Clear() {
  header_length_ = 0;
  body_length_ = 0;
  header_ = NULL;
  body_ = NULL;
  hardware_type_ = 0;
  protocol_type_ = 0;
  hardware_len_ = 0;
  protocol_len_ = 0;
  op_ = 0;
  sender_mac_.set_addr(NULL);
  recver_mac_.set_addr(NULL);
  sender_ip_.Clear();
  recver_ip_.Clear();
}

void ArpParser::Show() const {
  cout << protocol_name_ << endl;
  cout << "Header length is: " << header_length_ << endl;
  cout << "Body length is: " << body_length_ << endl;
  cout << "Hardware type is: " << ( hardware_type_ == PE::ARP_HARDWARE_TYPE_MAC? "MAC":"UNKOWN" ) << endl;
  cout << "Protocol type is: " << ( protocol_type_ == PE::ARP_PROTOCOL_TYPE_IP? "IP":"UNKONW") << endl;
  cout << "Hardware address length is: " << hardware_len_ << endl;
  cout << "Protocol address length is: " << protocol_len_ << endl;
  switch(op_) {
    case 1: // ARP_OP_ARP_REQUEST
      cout << "Operation is ARP Request" << endl;
      break;
    case 2: // ARP_OP_ARP_REPLY
      cout << "Operation is ARP Reply" << endl;
      break;
    case 3: // ARP_OP_RARP_REQUEST
      cout << "Operation is RARP Request" << endl;
      break;
    case 4: // ARP_OP_RARP_REPLY
      cout << "Operation is RARP Reply" << endl;
      break;
    default:
      cout << "Operation is UNKOWN" << endl;
      break;
  }
  cout << "Sender's MAC is: " << sender_mac_.ToString() << endl;
  cout << "Sender's IP is: " << sender_ip_.ToString() << endl;
  cout << "Reciever's MAC is: " << recver_mac_.ToString() << endl;
  cout << "Reciever's IP is: " << recver_ip_.ToString() << endl;
}

} /* namespace ucas_sniffer */
