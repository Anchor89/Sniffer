/*
 * MacParser.h
 *
 *  Created on: 2012-9-27
 *      Author: Anchor
 */

#ifndef MACPARSER_H_
#define MACPARSER_H_

#include <cstring>
#include <string>
#include <iostream>

#include "ProtocolEnumerate.h"
#include "ProtocolParserBase.h"
#include "InternetAddresses.h"
#include "util.h"

using std::memcpy;
using std::string;

namespace ucas_sniffer {

// Description:
//    Parse a buffer which should be a frame of MAC.
//
//    In a MAC frame:
//      The first 6 bytes is destination address;
//      The following 6 bytes is source address;
//      The following 2 bytes is type:
//        0x0800: IP
//        0x0806: ARP request/reply
//        0x8035: RARP request/reply

class MacParser: public ucas_sniffer::ProtocolParserBase {
  public:
    MacParser();
    virtual ~MacParser();

    /* Constant for MAC protocol */
    static const unsigned int MAC_FRAME_MIN_LEN;

    /* The type of data */
    static const unsigned short MAC_TYPE_IP;
    static const unsigned short MAC_TYPE_ARP;
    static const unsigned short MAC_TYPE_RARP;

    virtual bool Parse(const unsigned char* head, const unsigned int len);

    virtual void Clear();

    virtual void Show() const;

    const MacAddress& dst_addr() const {
      return dst_addr_;
    }

    const MacAddress& src_addr() const {
      return src_addr_;
    }

    unsigned short type() const {
      return type_;
    }

  private:
    MacAddress dst_addr_;
    MacAddress src_addr_;
    unsigned short type_;
};

} /* namespace ucas_sniffer */
#endif /* MACPARSER_H_ */
