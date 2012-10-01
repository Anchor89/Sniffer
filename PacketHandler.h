/*
 * PacketHandler.h
 *
 *  Created on: 2012-9-28
 *      Author: Anchor
 */

#ifndef PACKETHANDLER_H_
#define PACKETHANDLER_H_

#include <memory>
#include <vector>

#include "ArpParser.h"
#include "Ipv4Parser.h"
#include "MacParser.h"
#include "IcmpParser.h"
#include "IgmpParser.h"
#include "TcpParser.h"
#include "UdpParser.h"
#include "ProtocolEnumerate.h"

using std::auto_ptr;
using std::vector;

namespace ucas_sniffer {

class PacketHandler {
  public:
    PacketHandler();

    virtual ~PacketHandler();

    void PointTo(const unsigned char* data, const unsigned int size);

    void MakeCopy(const unsigned char* data, const unsigned int size);

    void Parse();

    void Show() const;

    void Clear();

    const unsigned char* data() const {
      return data_;
    }

    bool is_the_owner() const {
      return is_the_owner_;
    }

    int size() const {
      return size_;
    }

  private:
    // This data_ points to the packet data captured.
    // This pointer may be not the owner of the data.
    const unsigned char* data_;
    unsigned int size_;
    bool is_the_owner_;
    vector<ProtocolParserBase*> parser_stack_;
    auto_ptr<MacParser> mac_parser_;
    auto_ptr<ArpParser> arp_parser_;
    auto_ptr<Ipv4Parser> ipv4_parser_;
    auto_ptr<IcmpParser> icmp_parser_;
    auto_ptr<IgmpParser> igmp_parser_;
    auto_ptr<TcpParser> tcp_parser_;
    auto_ptr<UdpParser> udp_parser_;
};

} /* namespace ucas_sniffer */
#endif /* PACKETHANDLER_H_ */
