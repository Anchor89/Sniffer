/*
 * Util.cpp
 *
 *  Created on: 2012-9-27
 *      Author: Anchor
 */

#include "Util.h"

namespace ucas_sniffer {

unsigned char Assemble(const unsigned char* c0) {
  return *c0;
}

unsigned char Assemble(const unsigned char c0) {
  return c0;
}

unsigned short Assemble(const unsigned char* c0, const unsigned char* c1) {
  return *c0 << 8 | *c1;
}

unsigned short Assemble(const unsigned char c0, const unsigned char c1) {
  return c0 << 8 | c1;
}

// Arrange in the same order in memory
unsigned int Assemble(const unsigned char* c0, const unsigned char* c1, const unsigned char* c2, const unsigned char* c3) {
  return *c0 << 24 | *c1 << 16 | *c2 << 8 | *c3;
}

// Arrange in the same order in memory
unsigned int Assemble(const unsigned char c0, const unsigned char c1, const unsigned char c2, const unsigned char c3) {
  return c0 << 24 | c1 << 16 | c2 << 8 | c3;
}

// Arrange in the same order in memory
unsigned short AssembleUint16(const unsigned char* c0) {
  return Assemble(c0, c0+1);
}

unsigned int AssembleUint32(const unsigned char* c0) {
  return Assemble(c0, c0+1, c0+2, c0+3);
}

} /* namespace ucas_sniffer */
