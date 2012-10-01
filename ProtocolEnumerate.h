/*
 * ProtocalEnumerate.h
 *
 *  Created on: 2012-9-28
 *      Author: Anchor
 */

#ifndef PROTOCOLENUMERATE_H_
#define PROTOCOLENUMERATE_H_

namespace ucas_sniffer {

// For short
#define PE ProtocolEnumerate

/* Here is all the enumerate information about the protocols */
class ProtocolEnumerate {
  public:
    ProtocolEnumerate() {
    }

    virtual ~ProtocolEnumerate() {
    }

    typedef const unsigned int CUINT32;

    static unsigned int ParseBuf(const unsigned char* data, CUINT32 offset, CUINT32 bitlen);

    /* NOTE: The unit of the number mentioned below is BIT */

    /* MAC */
    /* Format */
    static CUINT32 MAC_HEADER_LENGTH;
    static CUINT32 MAC_DST_ADDR_OFFSET;
    static CUINT32 MAC_DST_ADDR_BITLEN;
    static CUINT32 MAC_SRC_ADDR_OFFSET;
    static CUINT32 MAC_SRC_ADDR_BITLEN;
    static CUINT32 MAC_TYPE_OFFSET;
    static CUINT32 MAC_TYPE_BITLEN;
    /* Value */
    static CUINT32 MAC_TYPE_IP;
    static CUINT32 MAC_TYPE_ARP;
    static CUINT32 MAC_TYPE_RARP;

    /* ARP */
    /* Format info */
    static CUINT32 ARP_HEADER_LENGTH;
    static CUINT32 ARP_HARDWARE_TYPE_OFFSET;
    static CUINT32 ARP_HARDWARE_TYPE_BITLEN;
    static CUINT32 ARP_PROTOCOL_TYPE_OFFSET;
    static CUINT32 ARP_PROTOCOL_TYPE_BITLEN;
    static CUINT32 ARP_HARDWARE_LENGTH_OFFSET;
    static CUINT32 ARP_HARDWARE_LENGTH_BITLEN;
    static CUINT32 ARP_PROTOCOL_LENGTH_OFFSET;
    static CUINT32 ARP_PROTOCOL_LENGTH_BITLEN;
    static CUINT32 ARP_OP_OFFSET;
    static CUINT32 ARP_OP_BITLEN;
    static CUINT32 ARP_SENDER_MAC_OFFSET;
    static CUINT32 ARP_SENDER_MAC_BITLEN;
    static CUINT32 ARP_SENDER_IP_OFFSET;
    static CUINT32 ARP_SENDER_IP_BITLEN;
    static CUINT32 ARP_RECIEVER_MAC_OFFSET;
    static CUINT32 ARP_RECIEVER_MAC_BITLEN;
    static CUINT32 ARP_REVIEVER_IP_OFFSET;
    static CUINT32 ARP_REVIEVER_IP_BITLEN;
    /* Value */
    static CUINT32 ARP_HARDWARE_TYPE_MAC;
    static CUINT32 ARP_PROTOCOL_TYPE_IP;
    static CUINT32 ARP_OP_ARP_REQUEST;
    static CUINT32 ARP_OP_ARP_REPLY;
    static CUINT32 ARP_OP_RARP_REQUEST;
    static CUINT32 ARP_OP_RARP_REPLY;

    /* IP http://en.wikipedia.org/wiki/IPv4 */
    /* Format */
    static CUINT32 IP_VERSION_OFFSET;
    static CUINT32 IP_VERSION_BITLEN;
    static CUINT32 IP_HEADER_LENGTH_OFFSET;
    static CUINT32 IP_HEADER_LENGTH_BITLEN;
    static CUINT32 IP_TOS_OFFSET;
    static CUINT32 IP_TOS_BITLEN;
    static CUINT32 IP_TOTAL_LENGTH_OFFSET;
    static CUINT32 IP_TOTAL_LENGTH_BITLEN;
    static CUINT32 IP_ID_OFFSET;
    static CUINT32 IP_ID_BITLEN;
    static CUINT32 IP_FLAG_OFFSET;
    static CUINT32 IP_FLAG_BITLEN;
    static CUINT32 IP_FRAGMENT_OFFSET_OFFSET;
    static CUINT32 IP_FRAGMENT_OFFSET_BITLEN;
    static CUINT32 IP_TTL_OFFSET;
    static CUINT32 IP_TTL_BITLEN;
    static CUINT32 IP_PROTOCOL_OFFSET;
    static CUINT32 IP_PROTOCOL_BITLEN;
    static CUINT32 IP_CHECKSUM_OFFSET;
    static CUINT32 IP_CHECKSUM_BITLEN;
    static CUINT32 IP_SOURCE_ADDRESS_OFFSET;
    static CUINT32 IP_SOURCE_ADDRESS_BITLEN;
    static CUINT32 IP_DESTINATION_ADDRESS_OFFSET;
    static CUINT32 IP_DESTINATION_ADDRESS_BITLEN;
    static CUINT32 IP_OPTIONS_OFFSET;
    static CUINT32 IP_OPTIONS_BITLEN;
    /* Value */
    static CUINT32 IP_VERSION_IPV4;
    static CUINT32 IP_VERSION_IPV6;
    static CUINT32 IP_FLAG_DF;
    static CUINT32 IP_FLAG_MF;
    static CUINT32 IP_PROTOCOL_ICMP; // http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    static CUINT32 IP_PROTOCOL_IGMP;
    static CUINT32 IP_PROTOCOL_IPV4;
    static CUINT32 IP_PROTOCOL_TCP;
    static CUINT32 IP_PROTOCOL_UDP;

    /* ICMP http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol */
    /* Format */
    static CUINT32 ICMP_TYPE_OFFSET;
    static CUINT32 ICMP_TYPE_BITLEN;
    static CUINT32 ICMP_CODE_OFFSET;
    static CUINT32 ICMP_CODE_BITLEN;
    static CUINT32 ICMP_CHECKSUM_OFFSET;
    static CUINT32 ICMP_CHECKSUM_BITLEN;
    static CUINT32 ICMP_REST_OF_HEADER_OFFSET;
    /* Value */
    // There is a table which describe all the possibilities of type and code at:
    //  http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

    /* IGMP http://en.wikipedia.org/wiki/Internet_Group_Management_Protocol */
    /* Format */
    static CUINT32 IGMP_TYPE_OFFSET;
    static CUINT32 IGMP_TYPE_BITLEN;
    static CUINT32 IGMP_MAX_RESP_TIME_OFFSET;
    static CUINT32 IGMP_MAX_RESP_TIME_BITLEN;
    static CUINT32 IGMP_CHECKSUM_OFFSET;
    static CUINT32 IGMP_CHECKSUM_BITLEN;
    static CUINT32 IGMP_GROUP_ADDRESS_OFFSET;
    static CUINT32 IGMP_GROUP_ADDRESS_BITLEN;
    static CUINT32 IGMPv3_RESV_OFFSET;
    static CUINT32 IGMPv3_RESV_BITLEN;
    static CUINT32 IGMPv3_S_OFFSET;
    static CUINT32 IGMPv3_S_BITLEN;
    static CUINT32 IGMPv3_QRV_OFFSET;
    static CUINT32 IGMPv3_QRV_BITLEN;
    static CUINT32 IGMPv3_QQIC_OFFSET;
    static CUINT32 IGMPv3_QQIC_BITLEN;
    static CUINT32 IGMPv3_SOURCE_NUMBER_OFFSET;
    static CUINT32 IGMPv3_SOURCE_NUMBER_BITLEN;
    /* Value */
    static CUINT32 IGMP_TYPE_MEMBERSHIP_QUERY;
    static CUINT32 IGMP_TYPE_MEMBERSHIP_REPORTv1;
    static CUINT32 IGMP_TYPE_MEMBERSHIP_REPORTv2;
    static CUINT32 IGMP_TYPE_MEMBERSHIP_REPORTv3;
    static CUINT32 IGMP_TYPE_LEAVE_GROUP;

    /* TCP http://en.wikipedia.org/wiki/Transmission_Control_Protocol */
    /* Format */
    static CUINT32 TCP_SOURCE_PORT_OFFSET;
    static CUINT32 TCP_SOURCE_PORT_BITLEN;
    static CUINT32 TCP_DESTINATION_PORT_OFFSET;
    static CUINT32 TCP_DESTINATION_PORT_BITLEN;
    static CUINT32 TCP_SEQUENCE_NUMBER_OFFSET;
    static CUINT32 TCP_SEQUENCE_NUMBER_BITLEN;
    static CUINT32 TCP_ACK_NUMBER_OFFSET;
    static CUINT32 TCP_ACK_NUMBER_BITLEN;
    static CUINT32 TCP_HEADER_LEN_OFFSET;
    static CUINT32 TCP_HEADER_LEN_BITLEN;
    static CUINT32 TCP_NS_OFFSET;
    static CUINT32 TCP_NS_BITLEN;
    static CUINT32 TCP_CWR_OFFSET;
    static CUINT32 TCP_CWR_BITLEN;
    static CUINT32 TCP_ECE_OFFSET;
    static CUINT32 TCP_ECE_BITLEN;
    static CUINT32 TCP_URG_OFFSET;
    static CUINT32 TCP_URG_BITLEN;
    static CUINT32 TCP_ACK_OFFSET;
    static CUINT32 TCP_ACK_BITLEN;
    static CUINT32 TCP_PSH_OFFSET;
    static CUINT32 TCP_PSH_BITLEN;
    static CUINT32 TCP_RST_OFFSET;
    static CUINT32 TCP_RST_BITLEN;
    static CUINT32 TCP_SYN_OFFSET;
    static CUINT32 TCP_SYN_BITLEN;
    static CUINT32 TCP_FIN_OFFSET;
    static CUINT32 TCP_FIN_BITLEN;
    static CUINT32 TCP_WINDOW_SIZE_OFFSET;
    static CUINT32 TCP_WINDOW_SIZE_BITLEN;
    static CUINT32 TCP_CHECKSUM_OFFSET;
    static CUINT32 TCP_CHECKSUM_BITLEN;
    static CUINT32 TCP_URG_POINTER_OFFSET;
    static CUINT32 TCP_URG_POINTER_BITLEN;
    static CUINT32 TCP_OPTIONS_OFFSET;
    /* Value */
    // No predefined value

    /* UDP http://en.wikipedia.org/wiki/User_Datagram_Protocol */
    /* Format */
    static CUINT32 UDP_SOURCE_PORT_OFFSET;
    static CUINT32 UDP_SOURCE_PORT_BITLEN;
    static CUINT32 UDP_DESTINATION_PORT_OFFSET;
    static CUINT32 UDP_DESTINATION_PORT_BITLEN;
    static CUINT32 UDP_LENGTH_OFFSET;
    static CUINT32 UDP_LENGTH_BITLEN;
    static CUINT32 UDP_CHECKSUM_OFFSET;
    static CUINT32 UDP_CHECKSUM_BITLEN;
    /* Value */
    // No predefined value
};


} /* namespace ucas_sniffer */
#endif /* PROTOCOLENUMERATE_H_ */
