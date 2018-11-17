#ifndef TUNSAFE_NETWORK_COMMON_H_
#define TUNSAFE_NETWORK_COMMON_H_

#include "netapi.h"

class PacketProcessor;

// A simple singlethreaded pool of packets used on windows where 
// FreePacket / AllocPacket are multithreded and thus slightly slower
#if defined(OS_WIN)
class SimplePacketPool {
public:
  explicit SimplePacketPool() {
    freed_packets_ = NULL;
    freed_packets_count_ = 0;
  }
  ~SimplePacketPool() {
    FreePacketList(freed_packets_);
  }
  Packet *AllocPacketFromPool() {
    if (Packet *p = freed_packets_) {
      freed_packets_ = Packet_NEXT(p);
      freed_packets_count_--;
      p->Reset();
      return p;
    }
    return AllocPacket();
  }
  void FreePacketToPool(Packet *p) {
    Packet_NEXT(p) = freed_packets_;
    freed_packets_ = p;
    freed_packets_count_++;
  }
  void FreeSomePackets() {
    if (freed_packets_count_ > 32)
      FreeSomePacketsInner();
  }
  void FreeSomePacketsInner();


  int freed_packets_count_;
  Packet *freed_packets_;
};
#else
class SimplePacketPool {
public:
  Packet *AllocPacketFromPool() {
    return AllocPacket();
  }
  void FreePacketToPool(Packet *packet) {
    return FreePacket(packet);
  }
};
#endif



// Aids with prefixing and parsing incoming and outgoing
// packets with the tcp protocol header.
class TcpPacketHandler {
public:
  explicit TcpPacketHandler(SimplePacketPool *packet_pool);
  ~TcpPacketHandler();

  // Adds a tcp header to a data packet so it can be transmitted on the wire
  void AddHeaderToOutgoingPacket(Packet *p);

  // Add a new chunk of incoming data to the packet list
  void QueueIncomingPacket(Packet *p);

  // Attempt to extract the next packet, returns NULL when complete.
  Packet *GetNextWireguardPacket();
  
  bool error() const { return error_flag_; }

private:
  // Internal function to read a packet
  Packet *ReadNextPacket(uint32 num);
 
  SimplePacketPool *packet_pool_;

  // Total # of bytes queued
  uint32 rqueue_bytes_;

  // Set if there's a fatal error
  bool error_flag_;

  // These hold the incoming packets before they're parsed
  Packet *rqueue_, **rqueue_end_;

  uint32 predicted_key_in_, predicted_key_out_;
  uint64 predicted_serial_in_, predicted_serial_out_;
};

#endif  // TUNSAFE_NETWORK_COMMON_H_