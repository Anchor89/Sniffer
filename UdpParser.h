/*
 * UdpParser.h
 *
 *  Created on: 2012-10-1
 *      Author: Anchor
 */

#ifndef UDPPARSER_H_
#define UDPPARSER_H_

#include "ProtocolParserBase.h"
#include "ProtocolEnumerate.h"

namespace ucas_sniffer {

class UdpParser: public ucas_sniffer::ProtocolParserBase {
  public:
    UdpParser();
    virtual ~UdpParser();

    // Parse the given buffer to get necessary information about this protocol
    virtual bool Parse(const unsigned char* head, const unsigned int len);

    // Clear all the data parsed from the buffer
    virtual void Clear();

    virtual void Show() const;

  private:
    unsigned short source_port_;
    unsigned short destination_port_;
    unsigned short length_;
    unsigned short checksum_;
};

} /* namespace ucas_sniffer */
#endif /* UDPPARSER_H_ */
