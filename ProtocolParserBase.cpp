/*
 * ProtocolParserBase.cpp
 *
 *  Created on: 2012-9-27
 *      Author: Anchor
 */

#include "ProtocolParserBase.h"

namespace ucas_sniffer {

ProtocolParserBase::ProtocolParserBase(const string& protocol_name) :
    protocol_name_(protocol_name){
  header_length_ = 0;
  body_length_ = 0;
  header_ = NULL;
  body_ = NULL;
}

ProtocolParserBase::~ProtocolParserBase() {
  // Nothing to do here
}

} /* namespace ucas_sniffer */
