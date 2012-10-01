/*
 * Interface.h
 *
 *  Created on: 2012-9-26
 *      Author: Anchor
 */

#ifndef INTERFACE_H_
#define INTERFACE_H_

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <winsock2.h>
#include "pcap.h"

#include "InternetAddresses.h"

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::vector;
using std::auto_ptr;

namespace ucas_sniffer {


/* This Class will store all the information in pcap_if_t */
class Interface {
  public:
    /* Internal representation of struct pcap_addr*/
    class IfAddress {
      public:
        IfAddress () {
          is_valid_ = false;
        }

        IfAddress (const pcap_addr* src) {
          if (src != NULL) {
            ParseFrom(src);
          }
        }

        IfAddress(const IfAddress& if_addr) {
          this->operator =(if_addr);
        }

        IfAddress& operator=(const IfAddress& if_addr) {
          is_valid_ = if_addr.IsValid();
          set_addr(if_addr.addr());
          set_netmask(if_addr.netmask());
          set_broadaddr(if_addr.broadaddr());
          set_dstaddr(if_addr.dstaddr());

          return *this;
        }

        void ParseFrom(const pcap_addr& src) {
          set_addr(src.addr);
          set_netmask(src.netmask);
          set_broadaddr(src.broadaddr);
          set_dstaddr(src.dstaddr);
        }

        void ParseFrom(const pcap_addr* src) {
          if (src != NULL) {
            ParseFrom(*src);
          }
          else {
            cerr << "IfAddress can not parse NULL" << endl;
          }
        }

        bool IsValid() const {
          return is_valid_;
        }

        void Show() const {
          cout << "Address: " << addr_.ToString() << endl;
          cout << "Network Mask: " << netmask_.ToString() << endl;
          cout << "Broadcast Address: " << broadaddr_.ToString() << endl;
          cout << "Destination Address: " << dstaddr_.ToString() << endl;
        }

        const IPv4Address& addr() const
        {
          return addr_;
        }

        void set_addr(const IPv4Address& addr)
        {
          addr_ = addr;
        }

        void set_addr(const sockaddr* addr) {
          if (addr != NULL) {
            addr_.set_addr(((sockaddr_in*)addr)->sin_addr);
          }
        }

        const IPv4Address& broadaddr() const
        {
          return broadaddr_;
        }

        void set_broadaddr(const IPv4Address& broadaddr)
        {
          broadaddr_ = broadaddr;
        }

        void set_broadaddr(const sockaddr* broadaddr) {
          if (broadaddr != NULL) {
            broadaddr_.set_addr(((sockaddr_in*)broadaddr)->sin_addr);
          }
        }

        const IPv4Address& dstaddr() const
        {
          return dstaddr_;
        }

        void set_dstaddr(const IPv4Address& dstaddr)
        {
          dstaddr_ = dstaddr;
        }

        void set_dstaddr(const sockaddr* dstaddr) {
          if (dstaddr != NULL) {
            dstaddr_.set_addr(((sockaddr_in*)dstaddr)->sin_addr);
          }
        }

        const IPv4Address& netmask() const
        {
          return netmask_;
        }

        void set_netmask(const IPv4Address& netmask)
        {
          netmask_ = netmask;
        }

        void set_netmask(const sockaddr* netmask) {
          if (netmask != NULL) {
            netmask_.set_addr(((sockaddr_in*)netmask)->sin_addr);
          }
        }

      private:
        bool is_valid_;

      private:
        // Data member
        IPv4Address addr_;
        IPv4Address netmask_;
        IPv4Address broadaddr_;
        IPv4Address dstaddr_;
    };

    Interface();

    Interface(const pcap_if_t* dev) {
      if (dev != NULL) {
        ParseFrom(dev);
      }
    }

    virtual ~Interface();

    bool ParseFrom(const pcap_if_t* dev);

    bool ParseFrom(const pcap_if_t& dev);

    // Begin to do pcap_loop
    // Return -3: This interface has no valid IPv4 address
    // Return -2: pcap_breakloop() was called
    // Return -1: Error occured
    // Return non-negative: Number of packets read
    int Capture(pcap_handler handler, int count = 0, unsigned char* user = NULL);

    // Begin to do pcap_dispatch
    // Return -3: This interface has no valid IPv4 address
    // Return -2: pcap_breakloop() was called
    // Return -1: Error occured
    // Return non-negative: Number of packets read
    int CaptureTimeout(pcap_handler handler, int timeout = 1000, int count = 0, unsigned char* user = NULL);

    // Begin to read all data from a file
    static int CaptureFromFile(const string& filename, pcap_handler handler, unsigned char* user);

    bool HasValidAddress() {
      return has_valid_addr_;
    }

    void Show();

    /* Settors and Gettors */
    const vector<IfAddress>& addresses() const {
      return addresses_;
    }

    void set_addresses(const vector<IfAddress>& addresses) {
      addresses_ .assign(addresses.begin(), addresses.end());
    }

    const string& description() const {
      return description_;
    }

    void set_description(const string& description) {
      description_ = description;
    }

    const string& name() const {
      return name_;
    }

    void set_name(const string& name) {
      name_ = name;
    }

    bool is_loopback() const {
      return is_loopback_;
    }

    void set_is_loopback(bool is_loopback) {
      is_loopback_ = is_loopback;
    }

  private:
    // Public interfaces support
    bool has_valid_addr_;

  private:
    // Data member
    string name_;
    string description_;
    vector<IfAddress> addresses_;
    bool is_loopback_;
};

} /* namespace ucas_sniffer */
#endif /* INTERFACE_H_ */
