#ifndef ROUTE_COMMON_H
#define ROUTE_COMMON_H

#include <cstdint>
#include <string>
#include <sstream>
#include <cmath>
#include "ns3/buffer.h"
#include "ns3/header.h"

namespace ns3 {

enum RouteCodepoint : uint8_t {
  CP_NRT_FILE           = 1,
  CP_NRT_ENTITY         = 2,
  CP_NRT_UNSIGNED_PKG   = 3,
  CP_NRT_SIGNED_PKG     = 4,
  CP_NEW_IS_TIMELINE_CHANGED = 5,
  CP_NEW_IS_TIMELINE_CONT    = 6,
  CP_REDUNDANT_IS       = 7,
  CP_MEDIA_FILE         = 8,
  CP_MEDIA_ENTITY       = 9,
  CP_MEDIA_FILE_CMAF_RA = 10
};

struct LctHeader
{
  uint8_t  V  = 1;
  uint8_t  C  = 0;
  bool     SPI = true;
  bool     Sflag = true;
  uint8_t  Oflag = 1;
  bool     Hflag = false;
  RouteCodepoint CP = CP_MEDIA_FILE;
  uint32_t CCI = 0;
  uint32_t TSI = 1;
  uint32_t TOI = 1;
  bool     extTolPresent  = false;
  uint64_t transferLength = 0;
  bool     extTimePresent = false;
  uint32_t ERTseconds     = 0;
};

struct SourceFecPayloadId
{
  uint32_t startOffset = 0;
};

enum RouteFecSymbolType : uint8_t {
  SYMBOL_SOURCE = 0,
  SYMBOL_REPAIR = 1
};

// ★★★ 修正：改為預設值，不再強制全域使用 ★★★
static const uint16_t DEFAULT_RAPTORQ_K = 1024;
static const uint16_t DEFAULT_RAPTORQ_R = 52;

// RaptorQ 成功機率 (近似)
inline double
RaptorQSuccessProb (uint32_t N, uint32_t K)
{
  if (N == 0 || K == 0) return 0.0;
  if (K > N) K = N;
  uint32_t extra = N - K;
  // RaptorQ 失敗率極低，約為 0.01^(overhead+1)
  double p = 1.0 - std::pow(0.01, static_cast<int>(extra) + 1);
  if (p < 0.0) p = 0.0;
  if (p > 1.0) p = 1.0;
  return p;
}

// Raptor (RFC 5053) 成功機率
inline double
RaptorSuccessProb (uint32_t N, uint32_t K)
{
  if (N < K) return 0.0;
  double overhead = static_cast<double>(N) - static_cast<double>(K);
  // Raptor 失敗率公式：Pf = 0.85 * 0.567^overhead
  double Pf = 0.85 * std::pow(0.567, overhead);
  double p = 1.0 - Pf;
  if (p < 0.0) p = 0.0;
  if (p > 1.0) p = 1.0;
  return p;
}

struct FecFrameHeader
{
  uint8_t  fecEncodingId = 130;
  uint8_t  instanceId    = 0;
  RouteFecSymbolType symbolType = SYMBOL_SOURCE;
  uint16_t sbn          = 0;
  uint32_t esi          = 0;
  uint32_t startOffset  = 0;
};

inline void SerializeLctAndFec(Buffer::Iterator &i, const LctHeader &h, const SourceFecPayloadId &fec)
{
  i.WriteU32(0x4C435431);
  uint32_t flags =
      ((h.V & 0xF) << 28) |
      ((h.C & 0x3) << 26) |
      ((h.SPI?1:0) << 25) |
      ((h.Sflag?1:0) << 24) |
      (((h.Oflag)&0x3) << 22) |
      ((h.Hflag?1:0) << 21) |
      (static_cast<uint8_t>(h.CP) & 0xFF);
  i.WriteU32(flags);
  i.WriteU32(h.CCI);
  i.WriteU32(h.TSI);
  i.WriteU32(h.TOI);
  i.WriteU8(h.extTolPresent ? 1 : 0);
  if (h.extTolPresent) { i.WriteU64(h.transferLength); }
  i.WriteU8(h.extTimePresent ? 1 : 0);
  if (h.extTimePresent) { i.WriteU32(h.ERTseconds); }
  i.WriteU32(fec.startOffset);
}

inline void DeserializeLctAndFec(Buffer::Iterator &i, LctHeader &h, SourceFecPayloadId &fec)
{
  (void)i.ReadU32();
  uint32_t flags = i.ReadU32();
  h.V = (flags >> 28) & 0xF;
  h.C = (flags >> 26) & 0x3;
  h.SPI   = ((flags >> 25) & 0x1) != 0;
  h.Sflag = ((flags >> 24) & 0x1) != 0;
  h.Oflag = (flags >> 22) & 0x3;
  h.Hflag = ((flags >> 21) & 0x1) != 0;
  h.CP    = static_cast<RouteCodepoint>(flags & 0xFF);
  h.CCI = i.ReadU32();
  h.TSI = i.ReadU32();
  h.TOI = i.ReadU32();
  h.extTolPresent = i.ReadU8() != 0;
  if (h.extTolPresent) { h.transferLength = i.ReadU64(); }
  h.extTimePresent = i.ReadU8() != 0;
  if (h.extTimePresent) { h.ERTseconds = i.ReadU32(); }
  fec.startOffset = i.ReadU32();
}

inline std::string MakeEfdtXml(uint32_t efdtVersion, uint64_t maxTransportSize,
                               const std::string &fileTemplate, uint64_t expiresEpochSec)
{
  std::ostringstream oss;
  oss << "<ExtendedFDT efdtVersion=\"" << efdtVersion << "\">\n";
  oss << "  <FDT-Instance Expires=\"" << expiresEpochSec << "\">\n";
  oss << "    <Extensions>\n";
  oss << "      <maxTransportSize>" << maxTransportSize << "</maxTransportSize>\n";
  oss << "      <fileTemplate>" << fileTemplate << "</fileTemplate>\n";
  oss << "    </Extensions>\n";
  oss << "  </FDT-Instance>\n";
  oss << "</ExtendedFDT>\n";
  return oss.str();
}

class RouteLctFecHeader : public Header
{
public:
  LctHeader          h;
  SourceFecPayloadId fec;
  FecFrameHeader     ff;

  static TypeId GetTypeId() {
    static TypeId tid = TypeId("ns3::RouteLctFecHeader")
      .SetParent<Header>()
      .AddConstructor<RouteLctFecHeader>();
    return tid;
  }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }

  void Print(std::ostream &os) const override {
    os << "TSI=" << h.TSI << " TOI=" << h.TOI;
  }
  uint32_t GetSerializedSize() const override {
    uint32_t size = 26;
    if (h.extTolPresent)  size += 8;
    if (h.extTimePresent) size += 4;
    size += 4; // fec payload id
    size += 13; // fec frame header
    return size;
  }
  void Serialize(Buffer::Iterator i) const override {
    Buffer::Iterator tmp = i;
    SerializeLctAndFec(tmp, h, fec);
    tmp.WriteU8 (ff.fecEncodingId);
    tmp.WriteU8 (ff.instanceId);
    tmp.WriteU8 (static_cast<uint8_t>(ff.symbolType));
    tmp.WriteU16(ff.sbn);
    tmp.WriteU32(ff.esi);
    tmp.WriteU32(ff.startOffset);
  }
  uint32_t Deserialize(Buffer::Iterator i) override {
    (void)i.ReadU32();
    uint32_t flags = i.ReadU32();
    h.V     = (flags >> 28) & 0xF;
    h.C     = (flags >> 26) & 0x3;
    h.SPI   = ((flags >> 25) & 0x1) != 0;
    h.Sflag = ((flags >> 24) & 0x1) != 0;
    h.Oflag = (flags >> 22) & 0x3;
    h.Hflag = ((flags >> 21) & 0x1) != 0;
    h.CP    = static_cast<RouteCodepoint>(flags & 0xFF);
    h.CCI = i.ReadU32();
    h.TSI = i.ReadU32();
    h.TOI = i.ReadU32();
    h.extTolPresent = i.ReadU8() != 0;
    if (h.extTolPresent) { h.transferLength = i.ReadU64(); }
    h.extTimePresent = i.ReadU8() != 0;
    if (h.extTimePresent) { h.ERTseconds = i.ReadU32(); }
    fec.startOffset = i.ReadU32();
    ff.fecEncodingId = i.ReadU8();
    ff.instanceId    = i.ReadU8();
    ff.symbolType    = static_cast<RouteFecSymbolType>(i.ReadU8());
    ff.sbn           = i.ReadU16();
    ff.esi           = i.ReadU32();
    ff.startOffset   = i.ReadU32();
    uint32_t size = 26;
    if (h.extTolPresent)  size += 8;
    if (h.extTimePresent) size += 4;
    size += 17;
    return size;
  }
};
}
#endif