/*
 * ArpParser.h
 *
 *  Created on: 2012-9-27
 *      Author: Anchor
 */

#ifndef ARPPARSER_H_
#define ARPPARSER_H_

#include <winsock2.h>

#include "InternetAddresses.h"
#include "ProtocolParserBase.h"
#include "MacParser.h"

namespace ucas_sniffer {

class ArpParser: public ucas_sniffer::ProtocolParserBase {
  public:
    ArpParser();
    virtual ~ArpParser();

    /* ARP constant value */
    static const unsigned short ARP_HARDWARE_TYPE_MAC;
    static const unsigned short ARP_PROTOCOL_TYPE_IP;
    static const unsigned short ARP_OP_ARP_REQUEST;
    static const unsigned short ARP_OP_ARP_REPLY;
    static const unsigned short ARP_OP_RARP_REQUEST;
    static const unsigned short ARP_OP_RARP_REPLY;

    static const unsigned int ARP_MIN_LEN;

    virtual bool Parse(const unsigned char* head, const unsigned int len);

    virtual void Clear();

    virtual void Show() const;

  private:
    unsigned short hardware_type_;
    unsigned short protocol_type_;
    unsigned short hardware_len_;
    unsigned short protocol_len_;
    unsigned short op_;
    MacAddress sender_mac_;
    MacAddress recver_mac_;
    IPv4Address sender_ip_;
    IPv4Address recver_ip_;
};

} /* namespace ucas_sniffer */
#endif /* ARPPARSER_H_ */
