/*
 * ProtocolParserBase.h
 *
 *  Created on: 2012-9-27
 *      Author: Anchor
 */

#ifndef PROTOCOLPARSERBASE_H_
#define PROTOCOLPARSERBASE_H_

#include <string>
#include <iostream>
#include <iomanip>
#include <bitset>

using std::bitset;
using std::cout;
using std::cerr;
using std::endl;
using std::hex;
using std::dec;
using std::string;
using std::setw;
using std::setfill;

namespace ucas_sniffer {

class ProtocolParserBase {
  public:
    ProtocolParserBase(const string& protocol_name = "");
    virtual ~ProtocolParserBase();

    // Parse the given buffer to get necessary information about this protocol
    virtual bool Parse(const unsigned char* head, const unsigned int len) = 0;

    // Clear all the data parsed from the buffer
    virtual void Clear() = 0;

    virtual void Show() const = 0;

    int header_length() const {
      return header_length_;
    }

    int body_length() const {
      return body_length_;
    }

    const unsigned char* header() const {
      return header_;
    }

    const unsigned char* body() const {
      return body_;
    }

    const string& protocol_name() const {
      return protocol_name_;
    }

  protected:
    unsigned int header_length_;
    unsigned int body_length_;
    const unsigned char* header_;
    const unsigned char* body_;
    const string protocol_name_;
};

} /* namespace ucas_sniffer */
#endif /* PROTOCOLPARSERBASE_H_ */
