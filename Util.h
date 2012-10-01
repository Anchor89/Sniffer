/*
 * Util.h
 *
 *  Created on: 2012-9-27
 *      Author: Anchor
 */

#ifndef UTIL_H_
#define UTIL_H_

namespace ucas_sniffer {

unsigned char Assemble(const unsigned char* c0);

unsigned char Assemble(const unsigned char c0);

unsigned short Assemble(const unsigned char* c0, const unsigned char* c1);

unsigned short Assemble(const unsigned char c0, const unsigned char c1);

unsigned int Assemble(const unsigned char* c0, const unsigned char* c1, const unsigned char* c2, const unsigned char* c3);

unsigned int Assemble(const unsigned char c0, const unsigned char c1, const unsigned char c2, const unsigned char c3);

unsigned short AssembleUint16(const unsigned char* c0);

unsigned int AssembleUint32(const unsigned char* c0);

} /* namespace ucas_sniffer */
#endif /* UTIL_H_ */
