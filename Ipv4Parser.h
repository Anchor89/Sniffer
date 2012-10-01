/*
 * Ipv4Parser.h
 *
 *  Created on: 2012-9-28
 *      Author: Anchor
 */

#ifndef IPV4PARSER_H_
#define IPV4PARSER_H_

#include "ProtocolEnumerate.h"
#include "ProtocolParserBase.h"
#include "InternetAddresses.h"

namespace ucas_sniffer {

class Ipv4Parser: public ucas_sniffer::ProtocolParserBase {
  public:
    Ipv4Parser();
    virtual ~Ipv4Parser();

    virtual bool Parse(const unsigned char* head, const unsigned int len);

    virtual void Clear();

    virtual void Show() const;

    const IPv4Address& destination_ip() const {
      return destination_ip_;
    }

    unsigned char flags() const {
      return flags_;
    }

    unsigned short fragment_offset() const {
      return fragment_offset_;
    }

    unsigned short header_checksum() const {
      return header_checksum_;
    }

    unsigned short id() const {
      return id_;
    }

    unsigned short protocol() const {
      return protocol_;
    }

    const IPv4Address& source_ip() const {
      return source_ip_;
    }

    unsigned char tos() const {
      return tos_;
    }

    unsigned short total_length() const {
      return total_length_;
    }

    unsigned short ttl() const {
      return ttl_;
    }

    unsigned short version() const {
      return version_;
    }

  private:
    unsigned short version_;
    unsigned char  tos_;
    unsigned short total_length_;
    unsigned short id_;
    unsigned char  flags_;
    unsigned short fragment_offset_;
    unsigned short ttl_;
    unsigned short protocol_;
    unsigned short header_checksum_;
    IPv4Address source_ip_;
    IPv4Address destination_ip_;
};

} /* namespace ucas_sniffer */
#endif /* IPV4PARSER_H_ */
