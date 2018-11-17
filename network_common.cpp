#include "stdafx.h"
#include "network_common.h"
#include "netapi.h"
#include "tunsafe_endian.h"
#include <assert.h>
#include <algorithm>
#include "util.h"

TcpPacketHandler::TcpPacketHandler(SimplePacketPool *packet_pool) {
  packet_pool_ = packet_pool;
  rqueue_bytes_ = 0;
  error_flag_ = false;
  rqueue_ = NULL;
  rqueue_end_ = &rqueue_;
  predicted_key_in_ = predicted_key_out_ = 0;
  predicted_serial_in_ = predicted_serial_out_ = 0;
}

TcpPacketHandler::~TcpPacketHandler() {
  FreePacketList(rqueue_);
}

enum {
  kTcpPacketType_Normal = 0,
  kTcpPacketType_Reserved = 1,
  kTcpPacketType_Data = 2,
  kTcpPacketType_Control = 3,
  kTcpPacketControlType_SetKeyAndCounter = 0,
};

void TcpPacketHandler::AddHeaderToOutgoingPacket(Packet *p) {
  unsigned int size = p->size;
  uint8 *data = p->data;
  if (size >= 16 && ReadLE32(data) == 4) {
    uint32 key = Read32(data + 4);
    uint64 serial = ReadLE64(data + 8);
    WriteBE16(data + 14, size - 16 + (kTcpPacketType_Data << 14));
    data += 14, size -= 14;
    // Insert a 15 byte control packet right before to set the new key/serial?
    if ((predicted_key_out_ ^ key) | (predicted_serial_out_ ^ serial)) {
      predicted_key_out_ = key;
      WriteLE64(data - 8, serial);
      Write32(data - 12, key);
      data[-13] = kTcpPacketControlType_SetKeyAndCounter;
      WriteBE16(data - 15, 13 + (kTcpPacketType_Control << 14));
      data -= 15, size += 15;
    }
    // Increase the serial by 1 for next packet.
    predicted_serial_out_ = serial + 1;
  } else {
    WriteBE16(data - 2, size);
    data -= 2, size += 2;
  }
  p->size = size;
  p->data = data;
}

void TcpPacketHandler::QueueIncomingPacket(Packet *p) {
  rqueue_bytes_ += p->size;
  p->queue_next = NULL;
  *rqueue_end_ = p;
  rqueue_end_ = &Packet_NEXT(p);
}

// Either the packet fits in one buf or not.
static uint32 ReadPacketHeader(Packet *p) {
  if (p->size >= 2)
    return ReadBE16(p->data);
  else
    return (p->data[0] << 8) + (Packet_NEXT(p)->data[0]);
}

// Move data around to ensure that exactly the first |num| bytes are stored
// in the first packet, and the rest of the data in subsequent packets.
Packet *TcpPacketHandler::ReadNextPacket(uint32 num) {
  Packet *p = rqueue_;

  assert(num <= kPacketCapacity);
  if (p->size < num) {
    // There's not enough data in the current packet, copy data from the next packet
    // into this packet.
    if ((uint32)(&p->data_buf[kPacketCapacity] - p->data) < num) {
      // Move data up front to make space.
      memmove(p->data_buf, p->data, p->size);
      p->data = p->data_buf;
    }
    // Copy data from future packets into p, and delete them should they become empty.
    do {
      Packet *n = Packet_NEXT(p);
      uint32 bytes_to_copy = std::min(n->size, num - p->size);
      uint32 nsize = (n->size -= bytes_to_copy);
      memcpy(p->data + postinc(p->size, bytes_to_copy), postinc(n->data, bytes_to_copy), bytes_to_copy);
      if (nsize == 0) {
        p->queue_next = n->queue_next;
        packet_pool_->FreePacketToPool(n);
      }
    } while (num - p->size);
  } else if (p->size > num) {
    // The packet has too much data. Split the packet into two packets.
    Packet *n = packet_pool_->AllocPacketFromPool();
    if (!n)
      return NULL; // unable to allocate a packet....?
    if (num * 2 <= p->size) {
      // There's a lot of trailing data: PP NNNNNN. Move PP.
      n->size = num;
      p->size -= num;
      rqueue_bytes_ -= num;
      memcpy(n->data, postinc(p->data, num), num);
      return n;
    } else {
      uint32 overflow = p->size - num;
      // There's a lot of leading data: PPPPPP NN. Move NN
      n->size = overflow;
      p->size = num;
      rqueue_ = n;
      if (!(n->queue_next = p->queue_next))
        rqueue_end_ = &Packet_NEXT(n);
      rqueue_bytes_ -= num;
      memcpy(n->data, p->data + num, overflow);
      return p;
    }
  }
  if ((rqueue_ = Packet_NEXT(p)) == NULL)
    rqueue_end_ = &rqueue_;
  rqueue_bytes_ -= num;
  return p;
}

Packet *TcpPacketHandler::GetNextWireguardPacket() {
  while (rqueue_bytes_ >= 2) {
    uint32 packet_header = ReadPacketHeader(rqueue_);
    uint32 packet_size = packet_header & 0x3FFF;
    uint32 packet_type = packet_header >> 14;
    if (packet_size + 2 > rqueue_bytes_)
      return NULL;
    if (packet_size + 2 > kPacketCapacity) {
      RERROR("Oversized packet?");
      error_flag_ = true;
      return NULL;
    }
    Packet *packet = ReadNextPacket(packet_size + 2);
    if (packet) {
//      RINFO("Packet of type %d, size %d", packet_type, packet->size - 2);
      packet->data += 2, packet->size -= 2;
      if (packet_type == kTcpPacketType_Normal) {

        return packet;
      } else if (packet_type == kTcpPacketType_Data) {
        // Optimization when the 16 first bytes are known and prefixed to the packet
        assert(packet->data >= packet->data_buf);

        packet->data -= 16, packet->size += 16;
        WriteLE32(packet->data, 4);
        Write32(packet->data + 4, predicted_key_in_);
        WriteLE64(packet->data + 8, predicted_serial_in_);
        predicted_serial_in_++;
        return packet;
      } else if (packet_type == kTcpPacketType_Control) {
        // Unknown control packets are silently ignored
        if (packet->size == 13 && packet->data[0] == kTcpPacketControlType_SetKeyAndCounter) {
          // Control packet to setup the predicted key/sequence nr
          predicted_key_in_ = Read32(packet->data + 1);
          predicted_serial_in_ = ReadLE64(packet->data + 5);
        }
        packet_pool_->FreePacketToPool(packet);
      } else {
        packet_pool_->FreePacketToPool(packet);
        error_flag_ = true;
        return NULL;
      }
    }
  }
  return NULL;
}