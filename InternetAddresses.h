/*
 * InternetAddresses.h
 *
 *  Created on: 2012-9-27
 *      Author: Anchor
 */

#ifndef INTERNETADDRESSES_H_
#define INTERNETADDRESSES_H_

#include <string>
#include <cstring>

#include <winsock2.h>

using std::string;
using std::memcpy;

namespace ucas_sniffer {

// MAC address has length of 6 bytes and can be formatted as "00:AA:BB:CC:DD:EE:" to a string
// of length 17
class MacAddress {
  public:
    MacAddress() {
      addr_ = new unsigned char[6];
      set_addr(0);
    }

    MacAddress(const unsigned char* mac_addr) {
      addr_ = new unsigned char[6];
      set_addr(mac_addr);
    }

    virtual ~MacAddress() {
      delete addr_;
    }

    void Clear() {
      set_addr(NULL);
    }

    const unsigned char* addr() const {
      return addr_;
    }

    const string ToString() const {
      return hex_str_;
    }

    void set_addr(const unsigned char* mac_addr) {
      if (mac_addr != 0) {
        memcpy(addr_, mac_addr, 6);
      }
      else {
        memcpy(addr_, "\0\0\0\0\0\0", 6);
      }
      ConvertNtoS();
    }

  private:
    void ConvertNtoS() {
      char hex_map[]  = "0123456789ABCDEF";
      hex_str_.clear();
      for (int i = 0; i < 6; i++) {
        hex_str_.push_back(hex_map[(addr_[i] >> 4) & 0x0F]);
        hex_str_.push_back(hex_map[addr_[i] & 0x0F]);
        if (i < 5) {
          hex_str_.push_back(':');
        }
      }
    }

    // Store the numerical format, NOT a C-style string.
    unsigned char* addr_;

    // Store the literal format in Hex
    string hex_str_;
};

class IPv4Address {
  public:
    IPv4Address(unsigned int addr = 0) {
      set_addr(addr);
    }

    IPv4Address(const in_addr& addr) {
      set_addr(addr);
    }

    IPv4Address(const IPv4Address& addr) {
      set_addr(addr.addr());
    }

    IPv4Address& operator=(const IPv4Address& addr) {
      set_addr(addr.addr());
      return *this;
    }
    void Clear() {
      addr_.S_un.S_addr = 0;
    }

    char* ToChar() const {
      return inet_ntoa(addr_);
    }

    string ToString() const {
      char* buf = inet_ntoa(addr_); // inet_ntoa own this buffer
      string rst(buf);
      return rst;
    }

    void ToString(string& str) {
      char* buf = inet_ntoa(addr_); // inet_ntoa own this buffer
      str.assign(buf);
    }

    const in_addr& addr() const {
      return addr_;
    }

    void set_addr(const in_addr& addr) {
      addr_ = addr;
    }

    void set_addr(const unsigned int addr) {
      // Because my machine is big-endian
      addr_.S_un.S_un_b.s_b1 = addr >> 24;
      addr_.S_un.S_un_b.s_b2 = addr >> 16;
      addr_.S_un.S_un_b.s_b3 = addr >> 8;
      addr_.S_un.S_un_b.s_b4 = addr;
    }

  private:
    in_addr addr_;
};
} /* namespace ucas_sniffer */
#endif /* INTERNETADDRESSES_H_ */
