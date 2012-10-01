/*
 * ProtocalEnumerate.cpp
 *
 *  Created on: 2012-9-28
 *      Author: Anchor
 */

#include <iostream>

#include "ProtocolEnumerate.h"
#include "Util.h"

using std::cerr;
using std::endl;

namespace ucas_sniffer {

typedef ProtocolEnumerate::CUINT32 CUINT32;

unsigned int PE::ParseBuf(const unsigned char* data,
                                CUINT32 offset,
                                CUINT32 bitlen) {
  if (data == NULL || bitlen == 0) {
    return 0;
  }

  if (bitlen > 32) {
    cerr << "ParseBuf can only handle value in range unsigned int" << endl;
  }

  unsigned int rst = 0;
  unsigned char mask;
  unsigned int rest_len;
  unsigned int part_len;
  if ((offset & 0x7) == 0 && (bitlen % 8 == 0)) {
    // Simple and common cases: The data is of 1,2,3 or 4 bytes
    if (bitlen == 32) {
      rst = AssembleUint32(data + (offset >> 3));
    }
    else if (bitlen == 24) {
      rst = Assemble(0, *data, *(data + 1), *(data + 2));
    }
    else if (bitlen == 16) {
      rst = AssembleUint16(data + (offset >> 3));
    }
    else if (bitlen == 8) {
      rst = data[offset >> 3];
    }
  }
  else if ((offset & 0x7) + bitlen <= 8) {
    // The second simple cases: The data wanted is less than a byte
    mask = ( 1 << bitlen ) - 1;
    rst = data[offset >> 3] >> (8 - (offset & 0x7) -bitlen) & mask;
  }
  else {
    // The most common case: Data starts from any bit and ends at any bit
    rest_len = bitlen;
    // Handle head
    if ((offset & 0x7) != 0) {
      part_len = 8 - (offset & 0x7);
      rest_len -= part_len;
      rst = data[offset >> 3] & (1 << part_len) - 1;
    }
    const unsigned char* cur = data + (offset >> 3) + 1;
    while (rest_len >= 8) {
      rst = rst << 8 | *cur;
      cur++;
      rest_len -= 8;
    }
    rst = rst << rest_len | (*cur >> (8 - rest_len));
  }

  return rst;
}

/* MAC */
/* Format */
CUINT32 ProtocolEnumerate::MAC_HEADER_LENGTH    = 14 << 3;
CUINT32 ProtocolEnumerate::MAC_DST_ADDR_OFFSET  = 0 << 3;
CUINT32 ProtocolEnumerate::MAC_DST_ADDR_BITLEN  = 6 << 3;
CUINT32 ProtocolEnumerate::MAC_SRC_ADDR_OFFSET  = 6 << 3;
CUINT32 ProtocolEnumerate::MAC_SRC_ADDR_BITLEN  = 6 << 3;
CUINT32 ProtocolEnumerate::MAC_TYPE_OFFSET      = 12 << 3;
CUINT32 ProtocolEnumerate::MAC_TYPE_BITLEN      = 2 << 3;
/* Value */
CUINT32 ProtocolEnumerate::MAC_TYPE_IP          = 0X0800;
CUINT32 ProtocolEnumerate::MAC_TYPE_ARP         = 0X0806;
CUINT32 ProtocolEnumerate::MAC_TYPE_RARP        = 0X8035;

/* ARP */
/* Format info */
CUINT32 ProtocolEnumerate::ARP_HEADER_LENGTH          = 28 << 3;
CUINT32 ProtocolEnumerate::ARP_HARDWARE_TYPE_OFFSET   = 0 << 3;
CUINT32 ProtocolEnumerate::ARP_HARDWARE_TYPE_BITLEN   = 2 << 3;
CUINT32 ProtocolEnumerate::ARP_PROTOCOL_TYPE_OFFSET   = 2 << 3;
CUINT32 ProtocolEnumerate::ARP_PROTOCOL_TYPE_BITLEN   = 2 << 3;
CUINT32 ProtocolEnumerate::ARP_HARDWARE_LENGTH_OFFSET = 4 << 3;
CUINT32 ProtocolEnumerate::ARP_HARDWARE_LENGTH_BITLEN = 1 << 3;
CUINT32 ProtocolEnumerate::ARP_PROTOCOL_LENGTH_OFFSET = 5 << 3;
CUINT32  ProtocolEnumerate::ARP_PROTOCOL_LENGTH_BITLEN= 1 << 3;
CUINT32 ProtocolEnumerate::ARP_OP_OFFSET              = 6 << 3;
CUINT32 ProtocolEnumerate::ARP_OP_BITLEN              = 2 << 3;
CUINT32 ProtocolEnumerate::ARP_SENDER_MAC_OFFSET      = 8 << 3;
CUINT32 ProtocolEnumerate::ARP_SENDER_MAC_BITLEN      = 6 << 3;
CUINT32 ProtocolEnumerate::ARP_SENDER_IP_OFFSET       = 14 << 3;
CUINT32 ProtocolEnumerate::ARP_SENDER_IP_BITLEN       = 4 << 3;
CUINT32 ProtocolEnumerate::ARP_RECIEVER_MAC_OFFSET    = 18 << 3;
CUINT32 ProtocolEnumerate::ARP_RECIEVER_MAC_BITLEN    = 6 << 3;
CUINT32 ProtocolEnumerate::ARP_REVIEVER_IP_OFFSET     = 24 << 3;
CUINT32 ProtocolEnumerate::ARP_REVIEVER_IP_BITLEN     = 4 << 3;
/* Value */
CUINT32 ProtocolEnumerate::ARP_HARDWARE_TYPE_MAC      = 1;
CUINT32 ProtocolEnumerate::ARP_PROTOCOL_TYPE_IP       = 0x0800;
CUINT32 ProtocolEnumerate::ARP_OP_ARP_REQUEST         = 1;
CUINT32 ProtocolEnumerate::ARP_OP_ARP_REPLY           = 2;
CUINT32 ProtocolEnumerate::ARP_OP_RARP_REQUEST        = 3;
CUINT32 ProtocolEnumerate::ARP_OP_RARP_REPLY          = 4;

/* IP http://en.wikipedia.org/wiki/IPv4 */
/* Format */
CUINT32 ProtocolEnumerate::IP_VERSION_OFFSET             = 0;
CUINT32 ProtocolEnumerate::IP_VERSION_BITLEN             = 4;
CUINT32 ProtocolEnumerate::IP_HEADER_LENGTH_OFFSET       = 4;
CUINT32 ProtocolEnumerate::IP_HEADER_LENGTH_BITLEN       = 4;
CUINT32 ProtocolEnumerate::IP_TOS_OFFSET                 = 8;
CUINT32 ProtocolEnumerate::IP_TOS_BITLEN                 = 8;
CUINT32 ProtocolEnumerate::IP_TOTAL_LENGTH_OFFSET        = 16;
CUINT32 ProtocolEnumerate::IP_TOTAL_LENGTH_BITLEN        = 16;
CUINT32 ProtocolEnumerate::IP_ID_OFFSET                  = 32;
CUINT32 ProtocolEnumerate::IP_ID_BITLEN                  = 16;
CUINT32 ProtocolEnumerate::IP_FLAG_OFFSET                = 48;
CUINT32 ProtocolEnumerate::IP_FLAG_BITLEN                = 3;
CUINT32 ProtocolEnumerate::IP_FRAGMENT_OFFSET_OFFSET     = 51;
CUINT32 ProtocolEnumerate::IP_FRAGMENT_OFFSET_BITLEN     = 13;
CUINT32 ProtocolEnumerate::IP_TTL_OFFSET                 = 64;
CUINT32 ProtocolEnumerate::IP_TTL_BITLEN                 = 8;
CUINT32 ProtocolEnumerate::IP_PROTOCOL_OFFSET            = 72;
CUINT32 ProtocolEnumerate::IP_PROTOCOL_BITLEN            = 8;
CUINT32 ProtocolEnumerate::IP_CHECKSUM_OFFSET            = 80;
CUINT32 ProtocolEnumerate::IP_CHECKSUM_BITLEN            = 16;
CUINT32 ProtocolEnumerate::IP_SOURCE_ADDRESS_OFFSET      = 96;
CUINT32 ProtocolEnumerate::IP_SOURCE_ADDRESS_BITLEN      = 32;
CUINT32 ProtocolEnumerate::IP_DESTINATION_ADDRESS_OFFSET = 128;
CUINT32 ProtocolEnumerate::IP_DESTINATION_ADDRESS_BITLEN = 32;
CUINT32 ProtocolEnumerate::IP_OPTIONS_OFFSET             = 160;
/* Value */
CUINT32 ProtocolEnumerate::IP_VERSION_IPV4               = 4;
CUINT32 ProtocolEnumerate::IP_VERSION_IPV6               = 6;
CUINT32 ProtocolEnumerate::IP_FLAG_DF                    = 2;
CUINT32 ProtocolEnumerate::IP_FLAG_MF                    = 1;
CUINT32 ProtocolEnumerate::IP_PROTOCOL_ICMP              = 1;
CUINT32 ProtocolEnumerate::IP_PROTOCOL_IGMP              = 2;
CUINT32 ProtocolEnumerate::IP_PROTOCOL_IPV4              = 4;
CUINT32 ProtocolEnumerate::IP_PROTOCOL_TCP               = 6;
CUINT32 ProtocolEnumerate::IP_PROTOCOL_UDP               = 17;

/* ICMP http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol */
/* Format */
CUINT32 ProtocolEnumerate::ICMP_TYPE_OFFSET           = 0;
CUINT32 ProtocolEnumerate::ICMP_TYPE_BITLEN           = 8;
CUINT32 ProtocolEnumerate::ICMP_CODE_OFFSET           = 8;
CUINT32 ProtocolEnumerate::ICMP_CODE_BITLEN           = 8;
CUINT32 ProtocolEnumerate::ICMP_CHECKSUM_OFFSET       = 16;
CUINT32 ProtocolEnumerate::ICMP_CHECKSUM_BITLEN       = 16;
CUINT32 ProtocolEnumerate::ICMP_REST_OF_HEADER_OFFSET = 32;
/* Value */
// There is a table which describe all the possibilities of type and code at:
//  http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

/* IGMP http://en.wikipedia.org/wiki/Internet_Group_Management_Protocol */
/* Format */
CUINT32 ProtocolEnumerate::IGMP_TYPE_OFFSET           = 0;
CUINT32 ProtocolEnumerate::IGMP_TYPE_BITLEN           = 8;
CUINT32 ProtocolEnumerate::IGMP_MAX_RESP_TIME_OFFSET  = 8;
CUINT32 ProtocolEnumerate::IGMP_MAX_RESP_TIME_BITLEN  = 8;
CUINT32 ProtocolEnumerate::IGMP_CHECKSUM_OFFSET       = 16;
CUINT32 ProtocolEnumerate::IGMP_CHECKSUM_BITLEN       = 16;
CUINT32 ProtocolEnumerate::IGMP_GROUP_ADDRESS_OFFSET  = 32;
CUINT32 ProtocolEnumerate::IGMP_GROUP_ADDRESS_BITLEN  = 32;
CUINT32 ProtocolEnumerate::IGMPv3_RESV_OFFSET         = 64;
CUINT32 ProtocolEnumerate::IGMPv3_RESV_BITLEN         = 4;
CUINT32 ProtocolEnumerate::IGMPv3_S_OFFSET            = 68;
CUINT32 ProtocolEnumerate::IGMPv3_S_BITLEN            = 1;
CUINT32 ProtocolEnumerate::IGMPv3_QRV_OFFSET          = 69;
CUINT32 ProtocolEnumerate::IGMPv3_QRV_BITLEN          = 3;
CUINT32 ProtocolEnumerate::IGMPv3_QQIC_OFFSET         = 72;
CUINT32 ProtocolEnumerate::IGMPv3_QQIC_BITLEN         = 8;
CUINT32 ProtocolEnumerate::IGMPv3_SOURCE_NUMBER_OFFSET= 80;
CUINT32 ProtocolEnumerate::IGMPv3_SOURCE_NUMBER_BITLEN= 16;
/* Value */
CUINT32 ProtocolEnumerate::IGMP_TYPE_MEMBERSHIP_QUERY    = 0x11;
CUINT32 ProtocolEnumerate::IGMP_TYPE_MEMBERSHIP_REPORTv1 = 0x12;
CUINT32 ProtocolEnumerate::IGMP_TYPE_MEMBERSHIP_REPORTv2 = 0x16;
CUINT32 ProtocolEnumerate::IGMP_TYPE_MEMBERSHIP_REPORTv3 = 0x22;
CUINT32 ProtocolEnumerate::IGMP_TYPE_LEAVE_GROUP         = 0x17;

/* TCP http://en.wikipedia.org/wiki/Transmission_Control_Protocol */
/* Format */
CUINT32 ProtocolEnumerate::TCP_SOURCE_PORT_OFFSET       = 0;
CUINT32 ProtocolEnumerate::TCP_SOURCE_PORT_BITLEN       = 16;
CUINT32 ProtocolEnumerate::TCP_DESTINATION_PORT_OFFSET  = 16;
CUINT32 ProtocolEnumerate::TCP_DESTINATION_PORT_BITLEN  = 16;
CUINT32 ProtocolEnumerate::TCP_SEQUENCE_NUMBER_OFFSET   = 32;
CUINT32 ProtocolEnumerate::TCP_SEQUENCE_NUMBER_BITLEN   = 32;
CUINT32 ProtocolEnumerate::TCP_ACK_NUMBER_OFFSET        = 64;
CUINT32 ProtocolEnumerate::TCP_ACK_NUMBER_BITLEN        = 32;
CUINT32 ProtocolEnumerate::TCP_HEADER_LEN_OFFSET        = 96;
CUINT32 ProtocolEnumerate::TCP_HEADER_LEN_BITLEN        = 4;
CUINT32 ProtocolEnumerate::TCP_NS_OFFSET                = 103;
CUINT32 ProtocolEnumerate::TCP_NS_BITLEN                = 1;
CUINT32 ProtocolEnumerate::TCP_CWR_OFFSET               = 104;
CUINT32 ProtocolEnumerate::TCP_CWR_BITLEN               = 1;
CUINT32 ProtocolEnumerate::TCP_ECE_OFFSET               = 105;
CUINT32 ProtocolEnumerate::TCP_ECE_BITLEN               = 1;
CUINT32 ProtocolEnumerate::TCP_URG_OFFSET               = 106;
CUINT32 ProtocolEnumerate::TCP_URG_BITLEN               = 1;
CUINT32 ProtocolEnumerate::TCP_ACK_OFFSET               = 107;
CUINT32 ProtocolEnumerate::TCP_ACK_BITLEN               = 1;
CUINT32 ProtocolEnumerate::TCP_PSH_OFFSET               = 108;
CUINT32 ProtocolEnumerate::TCP_PSH_BITLEN               = 1;
CUINT32 ProtocolEnumerate::TCP_RST_OFFSET               = 109;
CUINT32 ProtocolEnumerate::TCP_RST_BITLEN               = 1;
CUINT32 ProtocolEnumerate::TCP_SYN_OFFSET               = 110;
CUINT32 ProtocolEnumerate::TCP_SYN_BITLEN               = 1;
CUINT32 ProtocolEnumerate::TCP_FIN_OFFSET               = 111;
CUINT32 ProtocolEnumerate::TCP_FIN_BITLEN               = 1;
CUINT32 ProtocolEnumerate::TCP_WINDOW_SIZE_OFFSET       = 112;
CUINT32 ProtocolEnumerate::TCP_WINDOW_SIZE_BITLEN       = 16;
CUINT32 ProtocolEnumerate::TCP_CHECKSUM_OFFSET          = 128;
CUINT32 ProtocolEnumerate::TCP_CHECKSUM_BITLEN          = 16;
CUINT32 ProtocolEnumerate::TCP_URG_POINTER_OFFSET       = 144;
CUINT32 ProtocolEnumerate::TCP_URG_POINTER_BITLEN       = 16;
CUINT32 ProtocolEnumerate::TCP_OPTIONS_OFFSET           = 160;
/* Value */
// No predefined value

/* UDP http://en.wikipedia.org/wiki/User_Datagram_Protocol */
/* Format */
CUINT32 ProtocolEnumerate::UDP_SOURCE_PORT_OFFSET       = 0;
CUINT32 ProtocolEnumerate::UDP_SOURCE_PORT_BITLEN       = 16;
CUINT32 ProtocolEnumerate::UDP_DESTINATION_PORT_OFFSET  = 16;
CUINT32 ProtocolEnumerate::UDP_DESTINATION_PORT_BITLEN  = 16;
CUINT32 ProtocolEnumerate::UDP_LENGTH_OFFSET            = 32;
CUINT32 ProtocolEnumerate::UDP_LENGTH_BITLEN            = 16;
CUINT32 ProtocolEnumerate::UDP_CHECKSUM_OFFSET          = 48;
CUINT32 ProtocolEnumerate::UDP_CHECKSUM_BITLEN          = 16;
/* Value */
// No predefined value

} /* namespace ucas_sniffer */
