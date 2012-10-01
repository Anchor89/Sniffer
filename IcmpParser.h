/*
 * IcmpParser.h
 *
 *  Created on: 2012-10-1
 *      Author: Anchor
 */

#ifndef ICMPPARSER_H_
#define ICMPPARSER_H_

#include "ProtocolParserBase.h"
#include "ProtocolEnumerate.h"

namespace ucas_sniffer {

class IcmpParser: public ucas_sniffer::ProtocolParserBase {
  public:
    IcmpParser();
    virtual ~IcmpParser();

    // Parse the given buffer to get necessary information about this protocol
    virtual bool Parse(const unsigned char* head, const unsigned int len);

    // Clear all the data parsed from the buffer
    virtual void Clear();

    virtual void Show() const;

    unsigned short checksum() const {
      return checksum_;
    }

    unsigned short code() const {
      return code_;
    }

    unsigned short type() const {
      return type_;
    }

  private:
    unsigned short type_;
    unsigned short code_;
    unsigned short checksum_;
};

} /* namespace ucas_sniffer */
#endif /* ICMPPARSER_H_ */
