/*
 * TcpParser.cpp
 *
 *  Created on: 2012-10-1
 *      Author: Anchor
 */

#include "TcpParser.h"

namespace ucas_sniffer {

TcpParser::TcpParser() : ProtocolParserBase("TCP") {
  Clear();
}

TcpParser::~TcpParser() {
  // Nothing to do
}

bool TcpParser::Parse(const unsigned char* head, const unsigned int len) {
  if (head == NULL || len == 0) {
    return false;
  }

  source_port_ = PE::ParseBuf(head, PE::TCP_SOURCE_PORT_OFFSET, PE::TCP_SOURCE_PORT_BITLEN);
  destination_port_ = PE::ParseBuf(head, PE::TCP_DESTINATION_PORT_OFFSET, PE::TCP_DESTINATION_PORT_BITLEN);
  sequence_number_ = PE::ParseBuf(head, PE::TCP_SEQUENCE_NUMBER_OFFSET, PE::TCP_SEQUENCE_NUMBER_BITLEN);
  acknowledgment_number_ = PE::ParseBuf(head, PE::TCP_ACK_NUMBER_OFFSET, PE::TCP_ACK_NUMBER_BITLEN);
  header_length_ = PE::ParseBuf(head, PE::TCP_HEADER_LEN_OFFSET, PE::TCP_HEADER_LEN_BITLEN) << 2;
  ns_ = PE::ParseBuf(head, PE::TCP_NS_OFFSET, PE::TCP_NS_BITLEN);
  cwr_ = PE::ParseBuf(head, PE::TCP_CWR_OFFSET, PE::TCP_CWR_BITLEN);
  ece_ = PE::ParseBuf(head, PE::TCP_ECE_OFFSET, PE::TCP_ECE_BITLEN);
  urg_ = PE::ParseBuf(head, PE::TCP_URG_OFFSET, PE::TCP_URG_BITLEN);
  ack_ = PE::ParseBuf(head, PE::TCP_ACK_OFFSET, PE::TCP_ACK_BITLEN);
  psh_ = PE::ParseBuf(head, PE::TCP_PSH_OFFSET, PE::TCP_PSH_BITLEN);
  rst_ = PE::ParseBuf(head, PE::TCP_RST_OFFSET, PE::TCP_RST_BITLEN);
  syn_ = PE::ParseBuf(head, PE::TCP_SYN_OFFSET, PE::TCP_SYN_BITLEN);
  fin_ = PE::ParseBuf(head, PE::TCP_FIN_OFFSET, PE::TCP_FIN_BITLEN);
  window_size_ = PE::ParseBuf(head, PE::TCP_WINDOW_SIZE_OFFSET, PE::TCP_WINDOW_SIZE_BITLEN);
  checksum_ = PE::ParseBuf(head, PE::TCP_CHECKSUM_OFFSET, PE::TCP_CHECKSUM_BITLEN);
  urgent_pointer_ = PE::ParseBuf(head, PE::TCP_URG_POINTER_OFFSET, PE::TCP_URG_POINTER_BITLEN);
  if (header_length_ > 20) {
    options_ = head + ( PE::TCP_OPTIONS_OFFSET >> 3 );
  }
  else {
    options_ = NULL;
  }

  header_ = head;
  body_ = header_ + header_length_;
  body_length_ = len - header_length_;

  return true;
}

void TcpParser::Clear() {
  header_ = NULL;
  header_length_ = 0;
  body_ = NULL;
  body_length_ = 0;

  source_port_ = 0;
  destination_port_ = 0;
  sequence_number_ = 0;
  acknowledgment_number_ = 0;
  ns_ = 0;
  cwr_ = 0;
  ece_ = 0;
  urg_ = 0;
  ack_ = 0;
  psh_ = 0;
  rst_ = 0;
  syn_ = 0;
  fin_ = 0;
  window_size_ = 0;
  checksum_ = 0;
  urgent_pointer_ = 0;
  options_ = 0;
}

void TcpParser::Show() const {
  cout << protocol_name_ << endl;
  cout << "Header length: " << header_length_ << endl;
  cout << "Body length: " << body_length_ << endl;
  cout << "Source port: " << source_port_ << endl;
  cout << "Destination port: " << destination_port_ << endl;
  cout << "Sequence number: " << sequence_number_ << endl;
  cout << "Acknowledgment number: " << acknowledgment_number_ << endl;
  cout << "NS: " << (ns_ == 0 ? "Unset":"Set") << endl;
  cout << "CWR: " << (cwr_ == 0 ? "Unset":"Set") << endl;
  cout << "ECE: " << (ece_ == 0 ? "Unset":"Set") << endl;
  cout << "URG: " << (urg_ == 0 ? "Unset":"Set") << endl;
  cout << "ACK: " << (ack_ == 0 ? "Unset":"Set") << endl;
  cout << "PSH: " << (psh_ == 0 ? "Unset":"Set") << endl;
  cout << "RST: " << (rst_ == 0 ? "Unset":"Set") << endl;
  cout << "SYN: " << (syn_ == 0 ? "Unset":"Set") << endl;
  cout << "FIN: " << (fin_ == 0 ? "Unset":"Set") << endl;
  cout << "Window size: " << window_size_ << endl;
  cout << "Checksum: " << hex << checksum_ << dec << endl;
  if (urg_ != 0) {
    cout << "Urgent pointer" << hex << urgent_pointer_ << dec << endl;
  }
  if (header_length_ > 20) {
    cout << "Options: " << hex;
    for (int i=0; i<header_length_ - 20; i++) {
      cout.width(2);
      cout.fill('0');
      cout << static_cast<unsigned short>(options_[i]) << ' ';
    }
    cout << dec;
  }
}

} /* namespace ucas_sniffer */
