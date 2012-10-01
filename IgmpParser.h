/*
 * IgmpParser.h
 *
 *  Created on: 2012-10-1
 *      Author: Anchor
 */

#ifndef IGMPPARSER_H_
#define IGMPPARSER_H_

#include "ProtocolParserBase.h"
#include "ProtocolEnumerate.h"
#include "InternetAddresses.h"

namespace ucas_sniffer {

class IgmpParser: public ucas_sniffer::ProtocolParserBase {
  public:
    IgmpParser();
    virtual ~IgmpParser();

    // Parse the given buffer to get necessary information about this protocol
    virtual bool Parse(const unsigned char* head, const unsigned int len);

    // Clear all the data parsed from the buffer
    virtual void Clear();

    virtual void Show() const;

  private:
    unsigned char type_;
    unsigned short max_resp_time_;
    unsigned short checksum_;
    IPv4Address group_address_;
    unsigned char resv_;
    unsigned char s_;
    unsigned char qrv_;
    unsigned short qqic_;
    unsigned short source_number_;
};

} /* namespace ucas_sniffer */
#endif /* IGMPPARSER_H_ */
