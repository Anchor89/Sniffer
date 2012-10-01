/*
 * TcpParser.h
 *
 *  Created on: 2012-10-1
 *      Author: Anchor
 */

#ifndef TCPPARSER_H_
#define TCPPARSER_H_

#include "ProtocolParserBase.h"
#include "ProtocolEnumerate.h"

namespace ucas_sniffer {

class TcpParser: public ucas_sniffer::ProtocolParserBase {
  public:
    TcpParser();
    virtual ~TcpParser();

    // Parse the given buffer to get necessary information about this protocol
    virtual bool Parse(const unsigned char* head, const unsigned int len);

    // Clear all the data parsed from the buffer
    virtual void Clear();

    virtual void Show() const;

    unsigned char ack() const {
      return ack_;
    }

    unsigned int acknowledgment_number() const {
      return acknowledgment_number_;
    }

    unsigned short checksum() const {
      return checksum_;
    }

    unsigned char cwr() const {
      return cwr_;
    }

    unsigned short destination_port() const {
      return destination_port_;
    }

    unsigned char ece() const {
      return ece_;
    }

    unsigned char fin() const {
      return fin_;
    }

    unsigned char ns() const {
      return ns_;
    }

    const unsigned char* options() const {
      return options_;
    }

    unsigned char psh() const {
      return psh_;
    }

    unsigned char rst() const {
      return rst_;
    }

    unsigned int sequence_number() const {
      return sequence_number_;
    }

    unsigned short source_port() const {
      return source_port_;
    }

    unsigned char syn() const {
      return syn_;
    }

    unsigned char urg() const {
      return urg_;
    }

    unsigned short urgent_pointer() const {
      return urgent_pointer_;
    }

    unsigned short window_size() const {
      return window_size_;
    }

  private:
    unsigned short source_port_;
    unsigned short destination_port_;
    unsigned int sequence_number_;
    unsigned int acknowledgment_number_;
    unsigned char ns_;
    unsigned char cwr_;
    unsigned char ece_;
    unsigned char urg_;
    unsigned char ack_;
    unsigned char psh_;
    unsigned char rst_;
    unsigned char syn_;
    unsigned char fin_;
    unsigned short window_size_;
    unsigned short checksum_;
    unsigned short urgent_pointer_;
    const unsigned char* options_;
};

} /* namespace ucas_sniffer */
#endif /* TCPPARSER_H_ */
