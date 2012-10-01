/*
 * IgmpParser.cpp
 *
 *  Created on: 2012-10-1
 *      Author: Anchor
 */

#include "IgmpParser.h"
#include "Util.h"

namespace ucas_sniffer {

IgmpParser::IgmpParser() : ProtocolParserBase("IGMP") {
  Clear();
}

IgmpParser::~IgmpParser() {
  // Nothing to do
}

bool IgmpParser::Parse(const unsigned char* head, const unsigned int len) {
  if (head == NULL || len == 0) {
    return false;
  }

  header_ = head;
  header_length_ = len;
  body_ = NULL;
  body_length_ = 0;

  type_ = PE::ParseBuf(head, PE::IGMP_TYPE_OFFSET, PE::IGMP_TYPE_BITLEN);
  max_resp_time_ = PE::ParseBuf(head, PE::IGMP_MAX_RESP_TIME_OFFSET, PE::IGMP_MAX_RESP_TIME_BITLEN);
  checksum_ = PE::ParseBuf(head, PE::IGMP_CHECKSUM_OFFSET, PE::IGMP_CHECKSUM_BITLEN);
  group_address_.set_addr(PE::ParseBuf(head, PE::IGMP_GROUP_ADDRESS_OFFSET, PE::IGMP_GROUP_ADDRESS_BITLEN));
  if (type_ == PE::IGMP_TYPE_MEMBERSHIP_REPORTv3 ) {
    resv_ = PE::ParseBuf(head, PE::IGMPv3_RESV_OFFSET, PE::IGMPv3_RESV_BITLEN);
    s_ = PE::ParseBuf(head, PE::IGMPv3_S_OFFSET, PE::IGMPv3_S_BITLEN);
    qrv_ = PE::ParseBuf(head, PE::IGMPv3_QRV_OFFSET, PE::IGMPv3_QRV_BITLEN);
    qqic_ = PE::ParseBuf(head, PE::IGMPv3_QQIC_OFFSET, PE::IGMPv3_QQIC_BITLEN);
    source_number_ = PE::ParseBuf(head, PE::IGMPv3_SOURCE_NUMBER_OFFSET, PE::IGMPv3_SOURCE_NUMBER_BITLEN);
  }

  return true;
}

void IgmpParser::Clear() {
  header_ = NULL;
  header_length_ = 0;
  body_ = NULL;
  body_length_ = 0;

  type_ = 0;
  max_resp_time_ = 0;
  checksum_ = 0;
  group_address_.Clear();
  resv_ = 0;
  s_ = 0;
  qrv_ = 0;
  qqic_ = 0;
  source_number_ = 0;
}

void IgmpParser::Show() const {
  cout << protocol_name_ << endl;
  cout << "Header length: " << header_length_ << endl;
  cout << "Type: ";
  switch (type_) {
    case 0x12: // PE::IGMP_TYPE_MEMBERSHIP_REPORTv1:
      cout << "IGMPv1" << endl;
      break;
    case 0x16: // PE::IGMP_TYPE_MEMBERSHIP_REPORTv2:
      cout << "IGMPv2" << endl;
      break;
    case 0x22: // PE::IGMP_TYPE_MEMBERSHIP_REPORTv3:
      cout << "IGMPv3" << endl;
      break;
    case 0x17: // PE::IGMP_TYPE_LEAVE_GROUP:
      cout << "LEAVE_GROUP" << endl;
      break;
    case 0x11: // PE::IGMP_TYPE_MEMBERSHIP_QUERY:
      cout << "MEMBERSHIP_QUERY" << endl;
      break;
    default:
      cout << "Unknown" << endl;
      break;
  }
  cout << "Max response time: " << max_resp_time_ << endl;
  cout << "Checksum: " << hex << checksum_ << dec << endl;
  cout << "Group address: " << group_address_.ToString() << endl;
  if (type_ == PE::IGMP_TYPE_MEMBERSHIP_REPORTv3) {
    cout << "Suppress Router-side Processing Flag" << (s_ == 0? "Clear":"Set") << endl;
    cout << "Querier's Robustness Variable: " << bitset<3>(qrv_) << endl;
    cout << "Querier's Query Interval Code: " << qqic_ << endl;
    cout << "Number of sources: " << source_number_ << endl;
    for ( int i=0; i<source_number_; i++ ) {
      IPv4Address ip;
      ip.set_addr(AssembleUint32(header_ + 12 + i*4));
      cout << "Source " << i+1 << ": " << ip.ToString() << endl;
    }
  }
}

} /* namespace ucas_sniffer */
