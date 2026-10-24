/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *          
 */

 #define NS_LOG_APPEND_CONTEXT \
  if (m_node and m_connectionId) { std::clog << " [node " << m_node->GetId () << " socket " << m_connectionId << "] "; }


#include "ns3/abort.h"
#include "ns3/node.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/log.h"
#include "ns3/ipv4.h"
#include "ns3/ipv6.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv6-route.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv6-routing-protocol.h"
#include "ns3/simulation-singleton.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/random-variable-stream.h"
#include "ns3/nstime.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/pointer.h"
#include "ns3/trace-source-accessor.h"
#include "quic-socket-base.h"
#include "quic-congestion-ops.h"
#include "ns3/tcp-congestion-ops.h"
#include "quic-header.h"
#include "quic-l4-protocol.h"
#include "quic-l5-protocol.h"
#include "quic-stream-base.h"
#include "ns3/ipv4-end-point.h"
#include "ns3/ipv6-end-point.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/tcp-header.h"
#include "ns3/tcp-option-winscale.h"
#include "ns3/tcp-option-ts.h"
#include "ns3/tcp-option-sack-permitted.h"
#include "ns3/tcp-option-sack.h"
#include "ns3/rtt-estimator.h"
#include "fec-recovery-model.h"
// cm256.h 透過 fec-codec-cm256.h (在 quic-socket-base.h 中引入) 間接包含
#include "fec-codec-vdm.h"
#include <math.h>
#include <algorithm>
#include <vector>
#include <sstream>
#include <ns3/core-module.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicSocketBase");

//FEC統計
uint64_t g_fecRepairCount = 0;
uint64_t g_totalAppBytesSent = 0;
uint64_t g_totalWireBytesSent = 0;

// ★ 新增以下這段：建立全域的 FEC 日誌寫入器
#include <fstream>
#include <string>

static void LogFecEv(const std::string& ev, uint64_t caseId, uint32_t blk, int sid=-1, bool rep=false) {
  // 使用 std::ios::app 附加模式，避免覆蓋掉 test 腳本寫入的 DROP/DELIVER 事件
  std::ofstream log("events.csv", std::ios::out | std::ios::app);
  log << ns3::Simulator::Now().GetMicroSeconds() << ',' 
      << caseId << ',' << ev << ',' << blk << ',' << sid << ',' << (rep ? 1 : 0) << '\n';
}
// ★ 新增結束

// [Option2/Draft] FEC symbol = application payload only；大小固定等於 packetSize
static const uint32_t FEC_BLOCK_BYTES = 512;

NS_OBJECT_ENSURE_REGISTERED (QuicSocketBase);

const uint16_t QuicSocketBase::MIN_INITIAL_PACKET_SIZE = 1200;

TypeId
QuicSocketBase::GetInstanceTypeId () const
{
  return QuicSocketBase::GetTypeId ();
}

TypeId
QuicSocketBase::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicSocketBase")
    .SetParent<QuicSocket> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicSocketBase> ()
    .AddAttribute ("InitialVersion",
                   "Quic Version. The default value starts a version negotiation procedure",
                   UintegerValue (QUIC_VERSION_NEGOTIATION),
                   MakeUintegerAccessor (&QuicSocketBase::m_vers),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("IdleTimeout",
                   "Idle timeout value after which the socket is closed",
                   TimeValue (Seconds (300)),
                   MakeTimeAccessor (&QuicSocketBase::m_idleTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("MaxStreamData",
                   "Stream Maximum Data",
                   UintegerValue (4294967295),      // according to the QUIC RFC this value should default to 0, and be increased by the client/server
                   MakeUintegerAccessor (&QuicSocketBase::m_initial_max_stream_data),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxData",
                   "Connection Maximum Data",
                   UintegerValue (4294967295),      // according to the QUIC RFC this value should default to 0, and be increased by the client/server
                   MakeUintegerAccessor (&QuicSocketBase::m_max_data),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxStreamIdBidi",
                   "Maximum StreamId for Bidirectional Streams",
                   UintegerValue (2),                   // according to the QUIC RFC this value should default to 0, and be increased by the client/server
                   MakeUintegerAccessor (&QuicSocketBase::m_initial_max_stream_id_bidi),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute (
                   "MaxStreamIdUni", "Maximum StreamId for Unidirectional Streams",
                   UintegerValue (2),                   // according to the QUIC RFC this value should default to 0, and be increased by the client/server
                   MakeUintegerAccessor (&QuicSocketBase::m_initial_max_stream_id_uni),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute (
                   "MaxTrackedGaps", "Maximum number of gaps in an ACK",
                   UintegerValue (20),
                   MakeUintegerAccessor (&QuicSocketBase::m_maxTrackedGaps),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute (
                   "OmitConnectionId",
                   "Omit ConnectionId field in Short QuicHeader format",
                   BooleanValue (false),
                   MakeBooleanAccessor (&QuicSocketBase::m_omit_connection_id),
                   MakeBooleanChecker ())
    .AddAttribute (
                   "MaxPacketSize",
                   "Maximum Packet Size",
                   UintegerValue (1460),
                   MakeUintegerAccessor (&QuicSocketBase::GetSegSize,
                                         &QuicSocketBase::SetSegSize),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute (
                   "SocketSndBufSize",
                   "QuicSocketBase maximum transmit buffer size (bytes)",
                   UintegerValue (131072),                   // 128k
                   MakeUintegerAccessor (&QuicSocketBase::GetSocketSndBufSize,
                                         &QuicSocketBase::SetSocketSndBufSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute (
                   "SocketRcvBufSize",
                   "QuicSocketBase maximum receive buffer size (bytes)",
                   UintegerValue (131072),                   // 128k
                   MakeUintegerAccessor (&QuicSocketBase::GetSocketRcvBufSize,
                                         &QuicSocketBase::SetSocketRcvBufSize),
                   MakeUintegerChecker<uint32_t> ())
    //	.AddAttribute ("StatelessResetToken, "Stateless Reset Token",
    //				   UintegerValue (0),
    //				   MakeUintegerAccessor (&QuicSocketBase::m_stateless_reset_token),
    //				   MakeUintegerChecker<uint128_t> ())
    .AddAttribute (
                   "AckDelayExponent", "Ack Delay Exponent", UintegerValue (3),
                   MakeUintegerAccessor (&QuicSocketBase::m_ack_delay_exponent),
                   MakeUintegerChecker<uint8_t> ())
    .AddAttribute ("kMaxTLPs",
                   "Maximum number of tail loss probes before an RTO fires",
                   UintegerValue (2),
                   MakeUintegerAccessor (&QuicSocketState::m_kMaxTLPs),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute (
                   "kReorderingThreshold",
                   "Maximum reordering in packet number space before FACK style loss detection considers a packet lost",
                   UintegerValue (3),
                   MakeUintegerAccessor (&QuicSocketState::m_kReorderingThreshold),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute (
                   "kTimeReorderingFraction",
                   "Maximum reordering in time space before time based loss detection considers a packet lost",
                   DoubleValue (9 / 8),
                   MakeDoubleAccessor (&QuicSocketState::m_kTimeReorderingFraction),
                   MakeDoubleChecker<double> (0))
    .AddAttribute (
                   "kUsingTimeLossDetection",
                   "Whether time based loss detection is in use", BooleanValue (false),
                   MakeBooleanAccessor (&QuicSocketState::m_kUsingTimeLossDetection),
                   MakeBooleanChecker ())
    .AddAttribute (
                   "kMinTLPTimeout",
                   "Minimum time in the future a tail loss probe alarm may be set for",
                   TimeValue (MilliSeconds (10)),
                   MakeTimeAccessor (&QuicSocketState::m_kMinTLPTimeout),
                   MakeTimeChecker ())
    .AddAttribute (
                   "kMinRTOTimeout",
                   "Minimum time in the future an RTO alarm may be set for",
                   TimeValue (MilliSeconds (200)),
                   MakeTimeAccessor (&QuicSocketState::m_kMinRTOTimeout),
                   MakeTimeChecker ())
    .AddAttribute (
                   "kDelayedAckTimeout", "The length of the peer's delayed ACK timer",
                   TimeValue (MilliSeconds (25)),
                   MakeTimeAccessor (&QuicSocketState::m_kDelayedAckTimeout),
                   MakeTimeChecker ())
    .AddAttribute (
                   "kDefaultInitialRtt",
                   "The default RTT used before an RTT sample is taken",
                   TimeValue (MilliSeconds (100)),
                   MakeTimeAccessor (&QuicSocketState::m_kDefaultInitialRtt),
                   MakeTimeChecker ())
    .AddAttribute ("InitialSlowStartThreshold",
                   "QUIC initial slow start threshold (bytes)",
                   UintegerValue (INT32_MAX),
                   MakeUintegerAccessor (&QuicSocketBase::GetInitialSSThresh,
                                         &QuicSocketBase::SetInitialSSThresh),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("InitialPacketSize",
                   "QUIC initial slow start threshold (bytes)",
                   UintegerValue (1200),
                   MakeUintegerAccessor (&QuicSocketBase::GetInitialPacketSize,
                                         &QuicSocketBase::SetInitialPacketSize),
                   MakeUintegerChecker<uint32_t> (
                    QuicSocketBase::MIN_INITIAL_PACKET_SIZE, UINT32_MAX))
    //FEC
    .AddAttribute ("FecCodecType",
                   "FEC 編解碼器類型: \"cm256\" (Cauchy MDS, 預設) 或 \"vdm\" (Vandermonde RS)",
                   StringValue ("cm256"),
                   MakeStringAccessor (&QuicSocketBase::SetFecCodecType,
                                       &QuicSocketBase::GetFecCodecType),
                   MakeStringChecker ())
    .AddAttribute ("EnableFec",
                   "Enable Forward Error Correction (FEC) mechanism",
                   BooleanValue (false),
                   MakeBooleanAccessor (&QuicSocketBase::m_enableFec),
                   MakeBooleanChecker ())
    .AddAttribute ("FecK", 
                   "Number of Source Symbols (K) per FEC Block",
                   UintegerValue (0),
                   MakeUintegerAccessor (&QuicSocketBase::m_fecK),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("FecP", 
                   "Number of Repair Symbols (P) per FEC Block",
                   UintegerValue (0),
                   MakeUintegerAccessor (&QuicSocketBase::m_fecP),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("DisableRetransmission",
                   "Disable the retransmission mechanism (for FEC-only mode)",
                   BooleanValue (false),
                   MakeBooleanAccessor (&QuicSocketBase::m_disableRetransmission),
                   MakeBooleanChecker ())
    .AddAttribute ("RepairFlowControlEnabled",
                   "Enable flow control for FEC Repair packets",
                   BooleanValue (true),
                   MakeBooleanAccessor (&QuicSocketBase::m_repairFlowControlEnabled),
                   MakeBooleanChecker ())
    .AddAttribute ("RepairInterPacketInterval",
                   "Interval between FEC Repair packets when flow control is enabled",
                   TimeValue (MicroSeconds (100)),
                   MakeTimeAccessor (&QuicSocketBase::m_repairInterPacketInterval),
                   MakeTimeChecker ())
//    .AddAttribute (
//                   "LegacyCongestionControl",
//                   "When true, use TCP implementations for the congestion control",
//                   BooleanValue (false),
//                   MakeBooleanAccessor (&QuicSocketBase::m_quicCongestionControlLegacy),
//                   MakeBooleanChecker ())
    // .AddTraceSource ("RTO", "Retransmission timeout",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_rto),
    //                  "ns3::Time::TracedValueCallback").AddTraceSource (
    //     "IdleTO", "Idle timeout",
    //     MakeTraceSourceAccessor (&QuicSocketBase::m_idleTimeout),
    //     "ns3::Time::TracedValueCallback").AddTraceSource (
    //     "DrainingPeriodTO", "Draining Period timeout",
    //     MakeTraceSourceAccessor (&QuicSocketBase::m_drainingPeriodTimeout),
    //     "ns3::Time::TracedValueCallback");
    .AddTraceSource ("RTO",
                     "Retransmission timeout",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_rto),
                     "ns3::Time::TracedValueCallback")
    .AddTraceSource ("RTT",
                     "Last RTT sample",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_lastRtt),
                     "ns3::Time::TracedValueCallback")
    .AddTraceSource ("NextTxSequence",
                     "Next sequence number to send (SND.NXT)",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_nextTxSequenceTrace),
                     "ns3::SequenceNumber32TracedValueCallback")
    .AddTraceSource ("HighestSequence",
                     "Highest sequence number ever sent in socket's life time",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_highTxMarkTrace),
                     "ns3::SequenceNumber32TracedValueCallback")
    // .AddTraceSource ("State",
    //                  "TCP state",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_state),
    //                  "ns3::TcpStatesTracedValueCallback")
    .AddTraceSource ("CongState",
                     "TCP Congestion machine state",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_congStateTrace),
                     "ns3::TcpSocketState::TcpCongStatesTracedValueCallback")
    // .AddTraceSource ("AdvWND",
    //                  "Advertised Window Size",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_advWnd),
    //                  "ns3::TracedValueCallback::Uint32")
    // .AddTraceSource ("RWND",
    //                  "Remote side's flow control window",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_rWnd),
    //                  "ns3::TracedValueCallback::Uint32")
    // .AddTraceSource ("BytesInFlight",
    //                  "Socket estimation of bytes in flight",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_bytesInFlight),
    //                  "ns3::TracedValueCallback::Uint32")
    // .AddTraceSource ("HighestRxSequence",
    //                  "Highest sequence number received from peer",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_highRxMark),
    //                  "ns3::SequenceNumber32TracedValueCallback")
    // .AddTraceSource ("HighestRxAck",
    //                  "Highest ack received from peer",
    //                  MakeTraceSourceAccessor (&QuicSocketBase::m_highRxAckMark),
    //                  "ns3::SequenceNumber32TracedValueCallback")
    .AddTraceSource ("CongestionWindow",
                     "The TCP connection's congestion window",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_cWndTrace),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("SlowStartThreshold",
                     "TCP slow start threshold (bytes)",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_ssThTrace),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("Tx",
                     "Send QUIC packet to UDP protocol",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_txTrace),
                     "ns3::QuicSocketBase::QuicTxRxTracedCallback")
    .AddTraceSource ("Rx",
                     "Receive QUIC packet from UDP protocol",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_rxTrace),
                     "ns3::QuicSocketBase::QuicTxRxTracedCallback")
    /*
    //FEC
    .AddTraceSource ("FecTx",
                     "Send FEC Repair packet",
                     MakeTraceSourceAccessor (&QuicSocketBase::m_fecTxTrace),
                     "ns3::QuicSocketBase::QuicTxRxTracedCallback")
                     */
  ;
  return tid;
}

TypeId
QuicSocketState::GetTypeId (void)
{
  static TypeId tid =
    TypeId ("ns3::QuicSocketState")
    .SetParent<TcpSocketState> ()
    .SetGroupName ("Internet")
    .AddAttribute ("kMaxTLPs",
                   "Maximum number of tail loss probes before an RTO fires",
                   UintegerValue (2),
                   MakeUintegerAccessor (&QuicSocketState::m_kMaxTLPs),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kReorderingThreshold",
                   "Maximum reordering in packet number space before FACK style loss detection considers a packet lost",
                   UintegerValue (3),
                   MakeUintegerAccessor (&QuicSocketState::m_kReorderingThreshold),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("kTimeReorderingFraction",
                   "Maximum reordering in time space before time based loss detection considers a packet lost",
                   DoubleValue (9 / 8),
                   MakeDoubleAccessor (&QuicSocketState::m_kTimeReorderingFraction),
                   MakeDoubleChecker<double> (0))
    .AddAttribute ("kUsingTimeLossDetection",
                   "Whether time based loss detection is in use", BooleanValue (false),
                   MakeBooleanAccessor (&QuicSocketState::m_kUsingTimeLossDetection),
                   MakeBooleanChecker ())
    .AddAttribute ("kMinTLPTimeout",
                   "Minimum time in the future a tail loss probe alarm may be set for",
                   TimeValue (MilliSeconds (10)),
                   MakeTimeAccessor (&QuicSocketState::m_kMinTLPTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("kMinRTOTimeout",
                   "Minimum time in the future an RTO alarm may be set for",
                   TimeValue (MilliSeconds (200)),
                   MakeTimeAccessor (&QuicSocketState::m_kMinRTOTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("kDelayedAckTimeout", "The lenght of the peer's delayed ack timer",
                   TimeValue (MilliSeconds (25)),
                   MakeTimeAccessor (&QuicSocketState::m_kDelayedAckTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("kDefaultInitialRtt",
                   "The default RTT used before an RTT sample is taken",
                   TimeValue (MilliSeconds (100)),
                   MakeTimeAccessor (&QuicSocketState::m_kDefaultInitialRtt),
                   MakeTimeChecker ())
    .AddAttribute ("kMaxPacketsReceivedBeforeAckSend",
                   "The maximum number of packets without sending an ACK",
                   UintegerValue (20),
                   MakeUintegerAccessor (&QuicSocketState::m_kMaxPacketsReceivedBeforeAckSend),
                   MakeUintegerChecker<uint32_t> ());
  return tid;
}

QuicSocketState::QuicSocketState ()
  : TcpSocketState (),
    m_lossDetectionAlarm (),
    m_handshakeCount (0),
    m_tlpCount (
      0),
    m_rtoCount (0),
    m_largestSentBeforeRto (0),
    m_timeOfLastSentPacket (
      Seconds (0)),
    m_largestAckedPacket (0),
    m_smoothedRtt (Seconds (0)),
    m_rttVar (0),
    m_minRtt (
      Seconds (0)),
    m_maxAckDelay (Seconds (0)),
    m_lossTime (Seconds (0)),
    m_kMinimumWindow (
      2 * m_segmentSize),
    m_kLossReductionFactor (0.5),
    m_endOfRecovery (0),
    m_kMaxTLPs (
      2),
    m_kReorderingThreshold (3),
    m_kTimeReorderingFraction (9 / 8), //內建9/8
    m_kUsingTimeLossDetection (
      false),
    m_kMinTLPTimeout (MilliSeconds (10)),
    m_kMinRTOTimeout (
      MilliSeconds (200)),
    m_kDelayedAckTimeout (MilliSeconds (25)),
    m_alarmType (0),
    m_nextAlarmTrigger (Seconds (100)),
    m_kDefaultInitialRtt (
      MilliSeconds (100)),
    m_kMaxPacketsReceivedBeforeAckSend (20)
{
  m_lossDetectionAlarm.Cancel ();
}

QuicSocketState::QuicSocketState (const QuicSocketState &other)
  : TcpSocketState (other),
    m_lossDetectionAlarm (other.m_lossDetectionAlarm),
    m_handshakeCount (
      other.m_handshakeCount),
    m_tlpCount (other.m_tlpCount),
    m_rtoCount (
      other.m_rtoCount),
    m_largestSentBeforeRto (
      other.m_largestSentBeforeRto),
    m_timeOfLastSentPacket (
      other.m_timeOfLastSentPacket),
    m_largestAckedPacket (
      other.m_largestAckedPacket),
    m_smoothedRtt (
      other.m_smoothedRtt),
    m_rttVar (other.m_rttVar),
    m_minRtt (
      other.m_minRtt),
    m_maxAckDelay (other.m_maxAckDelay),
    m_lossTime (
      other.m_lossTime),
    m_kMinimumWindow (other.m_kMinimumWindow),
    m_kLossReductionFactor (
      other.m_kLossReductionFactor),
    m_endOfRecovery (
      other.m_endOfRecovery),
    m_kMaxTLPs (other.m_kMaxTLPs),
    m_kReorderingThreshold (
      other.m_kReorderingThreshold),
    m_kTimeReorderingFraction (
      other.m_kTimeReorderingFraction),
    m_kUsingTimeLossDetection (
      other.m_kUsingTimeLossDetection),
    m_kMinTLPTimeout (
      other.m_kMinTLPTimeout),
    m_kMinRTOTimeout (other.m_kMinRTOTimeout),
    m_kDelayedAckTimeout (
      other.m_kDelayedAckTimeout),
    m_kDefaultInitialRtt (
      other.m_kDefaultInitialRtt),
    m_kMaxPacketsReceivedBeforeAckSend (other.m_kMaxPacketsReceivedBeforeAckSend)
{
  m_lossDetectionAlarm.Cancel ();
}

QuicSocketBase::QuicSocketBase (void)
  : QuicSocket (),
    m_endPoint (0),
    m_endPoint6 (0),
    m_node (0),
    m_quicl4 (0),
    m_quicl5 (0),
    m_socketState (
      IDLE),
    m_transportErrorCode (
      QuicSubheader::TransportErrorCodes_t::NO_ERROR),
    m_serverBusy (false),
    m_errno (
      ERROR_NOTERROR),
    m_connected (false),
    m_connectionId (0),
    m_vers (
      QUIC_VERSION_NS3_IMPL),
    m_keyPhase (QuicHeader::PHASE_ZERO),
    m_lastReceived(Seconds(0.0)),
    m_initial_max_stream_data (
      0),
    m_max_data (0),
    m_initial_max_stream_id_bidi (0),
    m_idleTimeout (
      Seconds (300.0)),
    m_omit_connection_id (false),
    m_ack_delay_exponent (
      3),
    m_initial_max_stream_id_uni (0),
    m_maxTrackedGaps (20),
    m_receivedTransportParameters (
      false),
    m_couldContainTransportParameters (true),
    m_rto (
      Seconds (30.0)),
    m_drainingPeriodTimeout (Seconds (90.0)),
    m_congestionControl (
      0),
    m_lastRtt (Seconds(0.0)),
    m_queue_ack (false),
    m_numPacketsReceivedSinceLastAckSent (0),
    //FEC
    m_enableFec (false),
    m_fecK (0),
    m_fecP (0),
    m_currentBlockId (0),
    m_currentBlockIdx (0),
    m_currentRepairIdx (0),
    m_repairInterPacketInterval (MicroSeconds (100)),
    m_repairFlowControlEnabled (true),
    m_latePacketCount (0),
    m_fecRecoveredCount (0),
    m_sourcePacketSent (0),
    m_sourcePacketReceived (0),
    m_sourcePacketLost (0),
    m_repairPacketSent (0),
    m_repairPacketReceived (0),
    m_lastRecoveredBlockId (0),
    m_streamBytesReceived (0),
    m_isRetransmitting (false),
    m_hasPendingFecAck (false),
    m_fecAckSentCount (0),
    m_fecAckReceivedCount (0),
    m_disableRetransmission (false)
{
  NS_LOG_FUNCTION (this);

  m_fecCodec = std::make_unique<Cm256Codec> ();  // 預設使用 Cauchy MDS GF(256)

  m_rxBuffer = CreateObject<QuicSocketRxBuffer> ();
  m_txBuffer = CreateObject<QuicSocketTxBuffer> ();
  m_receivedPacketNumbers = std::vector<SequenceNumber32> ();

  m_tcb = CreateObject<QuicSocketState> ();
  m_tcb->m_cWnd = m_tcb->m_initialCWnd;
  m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;
  m_quicCongestionControlLegacy = false;
  /**
   * [IETF DRAFT 10 - Quic Transport: sec 5.7.1]
   *
   * The initial number for a packet number MUST be selected randomly from a range between
   * 0 and 2^32 -1025 (inclusive).
   * However, in this implementation, we set the sequence number to 0
   *
   */
  if (!m_quicCongestionControlLegacy)
    {
      Ptr<UniformRandomVariable> rand =
        CreateObject<UniformRandomVariable> ();
      m_tcb->m_nextTxSequence = SequenceNumber32 (0);
      // (uint32_t) rand->GetValue (0, pow (2, 32) - 1025));
    }

  // connect callbacks
  bool ok;
  ok = m_tcb->TraceConnectWithoutContext ("CongestionWindow",
                                          MakeCallback (&QuicSocketBase::UpdateCwnd, this));
  NS_ASSERT (ok == true);

  ok = m_tcb->TraceConnectWithoutContext ("SlowStartThreshold",
                                          MakeCallback (&QuicSocketBase::UpdateSsThresh, this));
  NS_ASSERT (ok == true);

  ok = m_tcb->TraceConnectWithoutContext ("CongState",
                                          MakeCallback (&QuicSocketBase::UpdateCongState, this));
  NS_ASSERT (ok == true);

  ok = m_tcb->TraceConnectWithoutContext ("NextTxSequence",
                                          MakeCallback (&QuicSocketBase::UpdateNextTxSequence, this));
  NS_ASSERT (ok == true);

  ok = m_tcb->TraceConnectWithoutContext ("HighestSequence",
                                          MakeCallback (&QuicSocketBase::UpdateHighTxMark, this));
}

QuicSocketBase::QuicSocketBase (const QuicSocketBase& sock)   // Copy constructor
  : QuicSocket (sock),
    m_endPoint (0),
    m_endPoint6 (0),
    m_node (sock.m_node),
    m_quicl4 (sock.m_quicl4),
    m_quicl5 (0),
    m_socketState (LISTENING),
    m_transportErrorCode (sock.m_transportErrorCode),
    m_serverBusy (sock.m_serverBusy),
    m_errno (sock.m_errno),
    m_connected (sock.m_connected),
    m_connectionId (0),
    m_vers (sock.m_vers),
    m_keyPhase (QuicHeader::PHASE_ZERO),
    m_lastReceived(sock.m_lastReceived),
    m_initial_max_stream_data (sock.m_initial_max_stream_data),
    m_max_data (sock.m_max_data),
    m_initial_max_stream_id_bidi (sock.m_initial_max_stream_id_bidi),
    m_idleTimeout (sock.m_idleTimeout),
    m_omit_connection_id (sock.m_omit_connection_id),
    m_ack_delay_exponent (sock.m_ack_delay_exponent),
    m_initial_max_stream_id_uni (sock.m_initial_max_stream_id_uni),
    m_maxTrackedGaps (sock.m_maxTrackedGaps),
    m_receivedTransportParameters (sock.m_receivedTransportParameters),
    m_couldContainTransportParameters (sock.m_couldContainTransportParameters),
    m_rto (sock.m_rto),
    m_drainingPeriodTimeout (sock.m_drainingPeriodTimeout),
    m_lastRtt (sock.m_lastRtt),
    m_quicCongestionControlLegacy (sock.m_quicCongestionControlLegacy),
    m_queue_ack (sock.m_queue_ack),
    m_numPacketsReceivedSinceLastAckSent (sock.m_numPacketsReceivedSinceLastAckSent),
    //FEC
    m_enableFec (sock.m_enableFec), // 複製設定：是否開啟
    m_fecK (sock.m_fecK),           // 複製設定：K 值
    m_fecP (sock.m_fecP),           // 複製設定：P 值
    m_currentBlockId (0),           // 狀態重置：新連線從 Block 0 開始
    m_currentBlockIdx (0),          // 狀態重置：Index 歸 0
    m_currentRepairIdx (0),         // 狀態重置：Repair Index 歸 0
    m_repairInterPacketInterval (sock.m_repairInterPacketInterval),
    m_repairFlowControlEnabled (sock.m_repairFlowControlEnabled),
    m_latePacketCount (sock.m_latePacketCount),
    m_fecRecoveredCount (0),
    m_sourcePacketSent (0),
    m_sourcePacketReceived (0),
    m_sourcePacketLost (0),
    m_repairPacketSent (0),
    m_repairPacketReceived (0),
    m_lastRecoveredBlockId (0),
    m_streamBytesReceived (0),
    m_isRetransmitting (false),
    m_hasPendingFecAck (false),
    m_fecAckSentCount (0),
    m_fecAckReceivedCount (0),
    m_disableRetransmission (sock.m_disableRetransmission),  // 複製設定：是否關閉重傳
    m_txTrace (sock.m_txTrace),
    m_rxTrace (sock.m_rxTrace)
    //m_fecTxTrace (sock.m_fecTxTrace)

{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC (this << " invoked the copy constructor");
  m_fecCodec = std::make_unique<Cm256Codec> ();  // 預設使用 Cauchy MDS GF(256)

//  Callback<void, Ptr< Socket > > vPS = MakeNullCallback<void, Ptr<Socket> > ();
//  Callback<void, Ptr<Socket>, const Address &> vPSA = MakeNullCallback<void, Ptr<Socket>, const Address &> ();
//  Callback<void, Ptr<Socket>, uint32_t> vPSUI = MakeNullCallback<void, Ptr<Socket>, uint32_t> ();
//  SetConnectCallback (vPS, vPS);
//  SetDataSentCallback (vPSUI);
//  SetSendCallback (vPSUI);
//  SetRecvCallback (vPS);
  m_txBuffer = CopyObject (sock.m_txBuffer);
  m_rxBuffer = CopyObject (sock.m_rxBuffer);
  m_receivedPacketNumbers = std::vector<SequenceNumber32> ();

  m_tcb = CopyObject (sock.m_tcb);
  if (sock.m_congestionControl)
    {
      m_congestionControl = sock.m_congestionControl->Fork ();
    }
  m_quicCongestionControlLegacy = sock.m_quicCongestionControlLegacy;

  /**
   * [IETF DRAFT 10 - Quic Transport: sec 5.7.1]
   *
   * The initial value for a packet number MUST be selected randomly from a range between
   * 0 and 2^32 -1025 (inclusive).
   *
   */
  if (!m_quicCongestionControlLegacy)
    {
      Ptr<UniformRandomVariable> rand =
        CreateObject<UniformRandomVariable> ();
      m_tcb->m_nextTxSequence = SequenceNumber32 (0);
      // (uint32_t) rand->GetValue (0, pow (2, 32) - 1025));
    }
}

QuicSocketBase::~QuicSocketBase (void)
{
  NS_LOG_FUNCTION (this);

  m_node = 0;
  if (m_endPoint != nullptr)
    {
      NS_ASSERT (m_quicl4 != nullptr);
      NS_ASSERT (m_endPoint != nullptr);
      m_quicl4->DeAllocate (m_endPoint);
      NS_ASSERT (m_endPoint == nullptr);
    }
  if (m_endPoint6 != nullptr)
    {
      NS_ASSERT (m_quicl4 != nullptr);
      NS_ASSERT (m_endPoint6 != nullptr);
      m_quicl4->DeAllocate (m_endPoint6);
      NS_ASSERT (m_endPoint6 == nullptr);
    }
  m_quicl4 = 0;
  //CancelAllTimers ();
}

/* Inherit from Socket class: Bind socket to an end-point in QuicL4Protocol */
int
QuicSocketBase::Bind (void)
{
  //NS_LOG_FUNCTION (this);
  m_endPoint = m_quicl4->Allocate ();
  if (0 == m_endPoint)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }

  m_quicl4->UdpBind (this);
  return SetupCallback ();
}

int
QuicSocketBase::Bind (const Address &address)
{
  NS_LOG_FUNCTION (this);
  if (InetSocketAddress::IsMatchingType (address))
    {
      InetSocketAddress transport = InetSocketAddress::ConvertFrom (address);
      Ipv4Address ipv4 = transport.GetIpv4 ();
      uint16_t port = transport.GetPort ();
      //SetIpTos (transport.GetTos ());
      if (ipv4 == Ipv4Address::GetAny () && port == 0)
        {
          m_endPoint = m_quicl4->Allocate ();
        }
      else if (ipv4 == Ipv4Address::GetAny () && port != 0)
        {
          m_endPoint = m_quicl4->Allocate (GetBoundNetDevice (), port);
        }
      else if (ipv4 != Ipv4Address::GetAny () && port == 0)
        {
          m_endPoint = m_quicl4->Allocate (ipv4);
        }
      else if (ipv4 != Ipv4Address::GetAny () && port != 0)
        {
          m_endPoint = m_quicl4->Allocate (GetBoundNetDevice (), ipv4, port);
        }
      if (0 == m_endPoint)
        {
          m_errno = port ? ERROR_ADDRINUSE : ERROR_ADDRNOTAVAIL;
          return -1;
        }
    }
  else if (Inet6SocketAddress::IsMatchingType (address))
    {
      Inet6SocketAddress transport = Inet6SocketAddress::ConvertFrom (address);
      Ipv6Address ipv6 = transport.GetIpv6 ();
      uint16_t port = transport.GetPort ();
      if (ipv6 == Ipv6Address::GetAny () && port == 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 ();
        }
      else if (ipv6 == Ipv6Address::GetAny () && port != 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 (GetBoundNetDevice (), port);
        }
      else if (ipv6 != Ipv6Address::GetAny () && port == 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 (ipv6);
        }
      else if (ipv6 != Ipv6Address::GetAny () && port != 0)
        {
          m_endPoint6 = m_quicl4->Allocate6 (GetBoundNetDevice (), ipv6, port);
        }
      if (0 == m_endPoint6)
        {
          m_errno = port ? ERROR_ADDRINUSE : ERROR_ADDRNOTAVAIL;
          return -1;
        }
    }
  else
    {
      m_errno = ERROR_INVAL;
      return -1;
    }

  m_quicl4->UdpBind (address, this);
  return SetupCallback ();
}

int
QuicSocketBase::Bind6 (void)
{
  NS_LOG_FUNCTION (this);
  m_endPoint6 = m_quicl4->Allocate6 ();
  if (0 == m_endPoint6)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }

  m_quicl4->UdpBind6 (this);
  return SetupCallback ();
}

/* Inherit from Socket class: Bind this socket to the specified NetDevice */
void
QuicSocketBase::BindToNetDevice (Ptr<NetDevice> netdevice)
{
  NS_LOG_FUNCTION (this);

  m_quicl4->BindToNetDevice (this, netdevice);
}

int
QuicSocketBase::Listen (void)
{
  NS_LOG_FUNCTION (this);
  if (m_socketType == NONE)
    {
      m_socketType = SERVER;
    }

  if (m_socketState != IDLE and m_socketState != QuicSocket::CONNECTING_SVR)
    {
      //m_errno = ERROR_INVAL;
      return -1;
    }

  NS_ASSERT (m_quicl4->SetListener (this));

  SetState (LISTENING);

  return 0;
}

int
QuicSocketBase::Connect (const Address & address)
{
  NS_LOG_FUNCTION (this);

  if (InetSocketAddress::IsMatchingType (address))
    {
      if (m_endPoint == nullptr)
        {
          if (Bind () == -1)
            {
              NS_ASSERT (m_endPoint == nullptr);
              return -1; // Bind() failed
            }
          NS_ASSERT (m_endPoint != nullptr);
        }
      InetSocketAddress transport = InetSocketAddress::ConvertFrom (address);
      m_endPoint->SetPeer (transport.GetIpv4 (), transport.GetPort ());
      //SetIpTos (transport.GetTos ());
      m_endPoint6 = nullptr;

      // Get the appropriate local address and port number from the routing protocol and set up endpoint
      /*if (SetupEndpoint () != 0)
        {
          NS_LOG_ERROR ("Route to destination does not exist ?!");
          return -1;
        }*/
    }
  else if (Inet6SocketAddress::IsMatchingType (address))
    {
      // If we are operating on a v4-mapped address, translate the address to
      // a v4 address and re-call this function
      Inet6SocketAddress transport = Inet6SocketAddress::ConvertFrom (address);
      Ipv6Address v6Addr = transport.GetIpv6 ();
      if (v6Addr.IsIpv4MappedAddress () == true)
        {
          Ipv4Address v4Addr = v6Addr.GetIpv4MappedAddress ();
          return Connect (InetSocketAddress (v4Addr, transport.GetPort ()));
        }

      if (m_endPoint6 == nullptr)
        {
          if (Bind6 () == -1)
            {
              NS_ASSERT (m_endPoint6 == nullptr);
              return -1; // Bind() failed
            }
          NS_ASSERT (m_endPoint6 != nullptr);
        }
      m_endPoint6->SetPeer (v6Addr, transport.GetPort ());
      m_endPoint = nullptr;

      // Get the appropriate local address and port number from the routing protocol and set up endpoint
      /*if (SetupEndpoint6 () != 0)
        {
          NS_LOG_ERROR ("Route to destination does not exist ?!");
          return -1;
        }*/
    }
  else
    {
      m_errno = ERROR_INVAL;
      return -1;
    }


  if (m_socketType == NONE)
    {
      m_socketType = CLIENT;
    }

  if (m_quicl5 == 0)
    {
      m_quicl5 = CreateStreamController ();
      m_quicl5->CreateStream (QuicStream::BIDIRECTIONAL, 0);   // Create Stream 0 (necessary)
    }

  // check if the address is in a list of known and authenticated addresses
  auto result = std::find (
      m_quicl4->GetAuthAddresses ().begin (), m_quicl4->GetAuthAddresses ().end (),
      InetSocketAddress::ConvertFrom (address).GetIpv4 ());

  if (result != m_quicl4->GetAuthAddresses ().end ()
      || m_quicl4->Is0RTTHandshakeAllowed ())
    {
      NS_LOG_INFO (
        "CONNECTION AUTHENTICATED Client found the Server " << InetSocketAddress::ConvertFrom (address).GetIpv4 () << " port " << InetSocketAddress::ConvertFrom (address).GetPort () << " in authenticated list");
      // connect the underlying UDP socket
      m_quicl4->UdpConnect (address, this);
      return DoFastConnect ();
    }
  else
    {
      NS_LOG_INFO (
        "CONNECTION not authenticated: cannot perform 0-RTT Handshake");
      // connect the underlying UDP socket
      m_quicl4->UdpConnect (address, this);
      return DoConnect ();
    }

}

/* Inherit from Socket class: Invoked by upper-layer application */
int
QuicSocketBase::Send (Ptr<Packet> p, uint32_t flags)
{
  NS_LOG_FUNCTION (this << flags);

  if (p->GetSize() > 0) {
      g_totalAppBytesSent += p->GetSize();
  }
  
  int data = 0;
  
  if (flags == 0)
    {
      data = Send (p);
    }
  else
    {
      data = m_quicl5->DispatchSend (p, flags);
      //FEC統計
      //if (p->GetSize() > 0) 
      //  { 
      //    g_totalAppBytesSent += p->GetSize();
      //  }
    }
  return data;
}

int
QuicSocketBase::Send (Ptr<Packet> p)
{
  NS_LOG_FUNCTION (this);

  //FEC統計
  //if (p->GetSize() > 0) {
  //    g_totalAppBytesSent += p->GetSize();
  //}
  //-------
  int data = m_quicl5->DispatchSend (p);

  return data;
}

int
QuicSocketBase::AppendingTx (Ptr<Packet> frame)
{
  NS_LOG_FUNCTION (this);

  if (m_socketState != IDLE)
    {
      bool done = m_txBuffer->Add (frame);
      if (!done)
        {
          NS_LOG_INFO ("Exceeding Socket Tx Buffer Size");
          m_errno = ERROR_MSGSIZE;
        }
      else
        {
          uint32_t win = AvailableWindow ();
          NS_LOG_DEBUG (
            "Added packet to the buffer - txBufSize = " << m_txBuffer->AppSize ()
                                                        << " AvailableWindow = " << win << " state " << QuicStateName[m_socketState]);
        }


      if (m_socketState != IDLE)
        {
          if (!m_sendPendingDataEvent.IsRunning ())
            {
              m_sendPendingDataEvent = Simulator::Schedule (
                  TimeStep (1), &QuicSocketBase::SendPendingData, this,
                  m_connected);
            }
        }
      if (done)
        {
          return frame->GetSize ();
        }
      return -1;
    }
  else
    {

      NS_ABORT_MSG ("Sending in state" << QuicStateName[m_socketState]);
      return -1;
    }
}

uint32_t
QuicSocketBase::SendPendingData (bool withAck)
{
  NS_LOG_FUNCTION (this << withAck);

  if (m_txBuffer->AppSize () == 0)
    {
      NS_LOG_INFO ("Nothing to send");
      return false;
    }

  uint32_t nPacketsSent = 0;

  // prioritize stream 0
  while (m_txBuffer->GetNumFrameStream0InBuffer () > 0)
    {
      NS_LOG_DEBUG ("Send a frame for stream 0");
      SequenceNumber32 next = ++m_tcb->m_nextTxSequence;
      NS_LOG_INFO ("SN " << m_tcb->m_nextTxSequence);

      uint32_t win = AvailableWindow ();
      uint32_t connWin = ConnectionWindow ();
      uint32_t bytesInFlight = BytesInFlight ();
      NS_LOG_DEBUG (
        "BEFORE stream 0 Available Window " << win
                                            << " Connection RWnd " << connWin
                                            << " BytesInFlight " << bytesInFlight
                                            << " BufferedSize " << m_txBuffer->AppSize ()
                                            << " MaxPacketSize " << GetSegSize ());

      SendDataPacket (next, 0, m_queue_ack);

      win = AvailableWindow ();
      connWin = ConnectionWindow ();
      bytesInFlight = BytesInFlight ();
      NS_LOG_DEBUG (
        "AFTER stream 0 Available Window " << win
                                           << " Connection RWnd " << connWin
                                           << " BytesInFlight " << bytesInFlight
                                           << " BufferedSize " << m_txBuffer->AppSize ()
                                           << " MaxPacketSize " << GetSegSize ());

      ++nPacketsSent;
    }
  uint32_t availableWindow = AvailableWindow ();

  while (availableWindow > 0 and m_txBuffer->AppSize () > 0)
    {
      // check the state of the socket!
      if (m_socketState == CONNECTING_CLT || m_socketState == CONNECTING_SVR)
        {
          NS_LOG_INFO ("CONNECTING_CLT and CONNECTING_SVR state; no data to transmit");
          break;
        }

      uint32_t availableData = m_txBuffer->AppSize ();

  	  if(availableData < availableWindow && availableData > 0)
  	  {
        NS_LOG_INFO("Ask the app for more data before trying to send");
  		  NotifySend(GetTxAvailable());
  	  }

      if (availableWindow < GetSegSize () and availableData > availableWindow)
        {
          NS_LOG_INFO ("Preventing Silly Window Syndrome. Wait to Send.");
          break;
        }

      // 發送 Source Packet
      SequenceNumber32 next = ++m_tcb->m_nextTxSequence;

      uint32_t s = std::min (availableWindow, GetSegSize ());

      uint32_t win = AvailableWindow ();
      uint32_t connWin = ConnectionWindow ();
      uint32_t bytesInFlight = BytesInFlight ();
      NS_LOG_DEBUG (
        "BEFORE Available Window " << win
                                   << " Connection RWnd " << connWin
                                   << " BytesInFlight " << bytesInFlight
                                   << " BufferedSize " << m_txBuffer->AppSize ()
                                   << " MaxPacketSize " << GetSegSize ());

      SendDataPacket (next, s, withAck);

      win = AvailableWindow ();
      connWin = ConnectionWindow ();
      bytesInFlight = BytesInFlight ();
      NS_LOG_DEBUG (
        "AFTER Available Window " << win
                                  << " Connection RWnd " << connWin
                                  << " BytesInFlight " << bytesInFlight
                                  << " BufferedSize " << m_txBuffer->AppSize ()
                                  << " MaxPacketSize " << GetSegSize ());

      ++nPacketsSent;

      availableWindow = AvailableWindow ();

    }

  if (nPacketsSent > 0)
    {
      NS_LOG_INFO ("SendPendingData sent " << nPacketsSent << " packets");
    }
  else
    {
      NS_LOG_INFO ("SendPendingData no packets sent");
    }

  return nPacketsSent;
}

void
QuicSocketBase::SetSegSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  NS_ABORT_MSG_UNLESS (m_socketState == IDLE || m_tcb->m_segmentSize == size,
                       "Cannot change segment size dynamically.");

  m_tcb->m_segmentSize = size;
  // Update minimum congestion window
  m_tcb->m_initialCWnd = 100000 * size;
  //m_tcb->m_initialCWnd = 2 * size;
  //m_tcb->m_kMinimumWindow = 2 * size; //FEC test
  m_tcb->m_kMinimumWindow = 100000 * size;
  m_tcb->m_cWnd = m_tcb->m_initialCWnd;
}

uint32_t
QuicSocketBase::GetSegSize (void) const
{
  return m_tcb->m_segmentSize;
}

void
QuicSocketBase::MaybeQueueAck ()
{
  NS_LOG_FUNCTION (this);
  ++m_numPacketsReceivedSinceLastAckSent;
  NS_LOG_INFO ("m_numPacketsReceivedSinceLastAckSent " << m_numPacketsReceivedSinceLastAckSent << " m_queue_ack " << m_queue_ack);

  // handle the list of m_receivedPacketNumbers
  if (m_receivedPacketNumbers.empty ())
    {
      NS_LOG_INFO ("Nothing to ACK");
      m_queue_ack = false;
      return;
    }

  // if(m_txBuffer->AppSize() > 0)
  // {
  //   NS_LOG_INFO("There are packets to be transmitted in the TX buffer, piggyback the ACK");
  //   return;
  // }

  if (m_numPacketsReceivedSinceLastAckSent > m_tcb->m_kMaxPacketsReceivedBeforeAckSend)
    {
      NS_LOG_INFO ("immediately send ACK - max number of unacked packets reached");
      m_queue_ack = true;
      if (!m_sendAckEvent.IsRunning ())
        {
          m_sendAckEvent = Simulator::Schedule (TimeStep (1), &QuicSocketBase::SendAck, this);
        }
    }

  if (HasReceivedMissing ())  // immediately queue the ACK
    {
      NS_LOG_INFO ("immediately send ACK - some packets have been received out of order");
      m_queue_ack = true;
      if (!m_sendAckEvent.IsRunning ())
        {
          m_sendAckEvent = Simulator::Schedule (TimeStep (1), &QuicSocketBase::SendAck, this);
        }
    }

  if (!m_queue_ack)
    {
      if (m_numPacketsReceivedSinceLastAckSent > 2) // QUIC decimation option
        {
          NS_LOG_INFO ("immediately send ACK - more than 2 packets received");
          m_queue_ack = true;
          if (!m_sendAckEvent.IsRunning ())
            {
              m_sendAckEvent = Simulator::Schedule (TimeStep (1), &QuicSocketBase::SendAck, this);
            }
        }
      else
        {
          if (!m_delAckEvent.IsRunning ())
            {
              NS_LOG_INFO ("Schedule a delayed ACK");
              // schedule a delayed ACK
              m_delAckEvent = Simulator::Schedule (
                  m_tcb->m_kDelayedAckTimeout, &QuicSocketBase::SendAck, this);
            }
          else
            {
              NS_LOG_INFO ("Delayed ACK timer already running");
            }
        }
    }
}

bool
QuicSocketBase::HasReceivedMissing ()
{
  // TODO implement this
  return false;
}

void
QuicSocketBase::SendAck ()
{
  NS_LOG_FUNCTION (this);
  m_delAckEvent.Cancel ();
  m_sendAckEvent.Cancel ();
  m_queue_ack = false;

  m_numPacketsReceivedSinceLastAckSent = 0;

  Ptr<Packet> p = Create<Packet> ();
  p->AddAtEnd (OnSendingAckFrame ());

  // [項目3] 將待發送的 FEC_ACK 附加到同一個封包中
  if (m_hasPendingFecAck)
    {
      Ptr<Packet> fecAckPkt = Create<Packet> ();
      fecAckPkt->AddHeader (m_pendingFecAckFrame);
      p->AddAtEnd (fecAckPkt);
      m_hasPendingFecAck = false;
      m_fecAckSentCount++;
      NS_LOG_INFO ("Piggybacked FEC_ACK #" << m_fecAckSentCount
                   << " RestoredPkts=" << m_pendingFecAckFrame.GetFecRestoredPackets ());
    }

  SequenceNumber32 packetNumber = ++m_tcb->m_nextTxSequence;

  QuicHeader head;

  head = QuicHeader::CreateShort (m_connectionId, packetNumber,
                                  !m_omit_connection_id, m_keyPhase);

  // if (m_socketState == CONNECTING_SVR)
  //   {
  //     m_connected = true;
  //     head = QuicHeader::CreateHandshake (m_connectionId, m_vers,
  //                                         packetNumber);
  //   }
  // else if (m_socketState == CONNECTING_CLT)
  //   {
  //     head = QuicHeader::CreateInitial (m_connectionId, m_vers, packetNumber);
  //   }
  // else if (m_socketState == OPEN)
  //   {
  //     if (!m_connected and !m_quicl4->Is0RTTHandshakeAllowed ())
  //       {
  //         m_connected = true;
  //         head = QuicHeader::CreateHandshake (m_connectionId, m_vers,
  //                                             packetNumber);
  //       }
  //     else if (!m_connected and m_quicl4->Is0RTTHandshakeAllowed ())
  //       {
  //         head = QuicHeader::Create0RTT (m_connectionId, m_vers,
  //                                        packetNumber);
  //         m_connected = true;
  //         m_keyPhase == QuicHeader::PHASE_ONE ? m_keyPhase =
  //                                                   QuicHeader::PHASE_ZERO :
  //                                               m_keyPhase =
  //                                                   QuicHeader::PHASE_ONE;
  //       }
  //     else
  //       {
  //         head = QuicHeader::CreateShort (m_connectionId, packetNumber,
  //                                         !m_omit_connection_id, m_keyPhase);
  //       }
  //   }
  // else
  //   {
  //     NS_FATAL_ERROR("ACK not possible in this state");
  //   }

  NS_LOG_INFO ("Send ACK packet with header " << head);
  m_quicl4->SendPacket (this, p, head);
  //FEC統計
  g_totalWireBytesSent += (p->GetSize () + 28);
  m_txTrace (p, head, this);
}

uint32_t
QuicSocketBase::SendDataPacket (SequenceNumber32 packetNumber,
                                uint32_t maxSize, bool withAck)
{
  NS_LOG_FUNCTION (this << packetNumber << maxSize << withAck);

  if (!m_drainingPeriodEvent.IsRunning ())
    {
      m_idleTimeoutEvent.Cancel ();
      NS_LOG_LOGIC (
        this << " SendDataPacket Schedule Close at time " << Simulator::Now ().GetSeconds () << " to expire at time " << (Simulator::Now () + m_idleTimeout.Get ()).GetSeconds ());
      m_idleTimeoutEvent = Simulator::Schedule (m_idleTimeout,
                                                &QuicSocketBase::Close, this);
    }
  else
    {
      return -1;
    }

  Ptr<Packet> p;

  if (m_txBuffer->GetNumFrameStream0InBuffer () > 0)
    {
      p = m_txBuffer->NextStream0Sequence (packetNumber);
      NS_ABORT_MSG_IF (p == 0, "No packet for stream 0 in the buffer!");
    }
  else
    {
      NS_LOG_LOGIC (
        this << " SendDataPacket - sending packet " << packetNumber.GetValue () << " of size " << maxSize << " at time " << Simulator::Now ().GetSeconds ());
      m_idleTimeoutEvent = Simulator::Schedule (m_idleTimeout,
                                                &QuicSocketBase::Close, this);
      p = m_txBuffer->NextSequence (maxSize, packetNumber);
    }

  uint32_t sz = p->GetSize ();

  // [Option2/Draft] 在 ACK 加入前預先捕捉 stream app payload（符合 draft 的 source symbol 定義）
  // p = [stream_subheader | app_payload]，PeekHeader 取得 subheader 大小後取末尾的 app data
  std::vector<uint8_t> fecPreCapture;
  uint64_t fecCapStreamId = 0;
  uint64_t fecCapOffset = 0;
  uint32_t fecCapLen = 0;
  if (m_enableFec && m_socketState == OPEN && sz > 0)
    {
      QuicSubheader peekSub;
      p->PeekHeader (peekSub);
      uint32_t streamHdrBytes = peekSub.GetSerializedSize ();
      if (sz > streamHdrBytes)
        {
          uint32_t appLen = sz - streamHdrBytes;
          fecPreCapture.resize (FEC_BLOCK_BYTES, 0);
          std::vector<uint8_t> tmp (sz);
          p->CopyData (tmp.data (), sz);
          std::memcpy (fecPreCapture.data (), tmp.data () + streamHdrBytes,
                       std::min (appLen, FEC_BLOCK_BYTES));
          // 記錄這個 source symbol 原本所屬的 stream 位置，供日後若此封包
          // 遺失、需要 FEC 復原時，重建出正確的 STREAM frame
          fecCapStreamId = peekSub.GetStreamId ();
          fecCapOffset = peekSub.GetOffset ();
          fecCapLen = std::min (appLen, FEC_BLOCK_BYTES);
        }
    }

  bool isAckOnly = ((sz == 0) & (withAck));

  if (withAck && !m_receivedPacketNumbers.empty ())
    {
      p->AddAtEnd (OnSendingAckFrame ());
    }

  //FEC
  bool needSendRepairs = false;
  uint32_t repairBlockId = 0;
  
  // 只有在以下條件全部滿足時才加入 FEC Tag：
  // 1. FEC 已啟用
  // 2. Socket 狀態為 OPEN
  // 3. 有實際資料要發送 (sz > 0)
  // 4. 這是應用層 stream 資料，而非 stream 0 上的 crypto/handshake 資料
  //
  // 舊版用 m_sourcePacketSent > 0 判斷「是否為資料發送方」，但
  // m_sourcePacketSent 只有在成功打上 FEC Tag 之後才會遞增，導致第一筆
  // 封包永遠無法通過判斷（雞生蛋問題），FEC 從未真正啟動。改用封包本身
  // 的 stream id 直接判斷是否為應用層資料。
  bool isDataSender = false;
  if (m_enableFec && m_socketState == OPEN && sz > 0)
    {
      QuicSubheader dsSub;
      p->PeekHeader (dsSub);
      isDataSender = dsSub.IsStream () && dsSub.GetStreamId () != 0;
    }

  if (m_enableFec && m_socketState == OPEN && sz > 0 && isDataSender)
    {
      // 建立 FEC TAG Frame (TagType=1 for Long Flow)
      // Tag ID Length = 3 (4 bytes) 支援較大的 Block ID
      QuicSubheader fecTag = QuicSubheader::CreateFecTag (
          1,                  // Tag Type: Long Flow
          m_currentBlockIdx,  // Sequence in Block
          3,                  // Tag ID Length
          m_currentBlockId,   // Tag ID (Block ID)
          0                   // Redundancy Ratio (Set to 0 as requested)
      );

      // 將 Tag 加到 Packet 最前面 (成為第一個 Frame)
      p->AddHeader (fecTag);

      // 更新統計大小 (選用，若要精確計算頻寬)
      sz += fecTag.GetSerializedSize();

      // [Option2/Draft] 儲存 pre-captured app payload 為此 source symbol
      if (!fecPreCapture.empty ())
        {
          auto &blockData = m_fecTxSrcData[m_currentBlockId];
          if (blockData.size () <= m_currentBlockIdx)
            blockData.resize (m_currentBlockIdx + 1);
          blockData[m_currentBlockIdx] = fecPreCapture;

          // 同步記錄這個 symbol 的原始 stream 位置，供 Repair 封包攜帶
          auto &blockMeta = m_fecTxSrcMeta[m_currentBlockId];
          if (blockMeta.size () <= m_currentBlockIdx)
            blockMeta.resize (m_currentBlockIdx + 1);
          blockMeta[m_currentBlockIdx] = FecSymbolMeta{fecCapStreamId, fecCapOffset, fecCapLen};
        }

      if (!m_isRetransmitting)
        {
          // [項目1] 只有原始封包才計入發送統計（重傳不計入，使 PLR 分母正確）
          m_sourcePacketSent++;
          NS_LOG_INFO ("FEC Source Sent: Block=" << m_currentBlockId << " Idx=" << m_currentBlockIdx);
          // ★ 新增：寫入發送紀錄到 events.csv
          LogFecEv("SEND", m_connectionId, m_currentBlockId);
        }
      else
        {
          NS_LOG_INFO ("FEC Retransmit Tagged: Block=" << m_currentBlockId << " Idx=" << m_currentBlockIdx);
        }



      // 更新計數器
      m_currentBlockIdx++;

      // 檢查是否滿了一個 Block
      repairBlockId = m_currentBlockId;
      if (m_currentBlockIdx >= m_fecK)
        {
          // Block 完成時，一律發送 Repair（包含重傳觸發完成的情況）
          NS_LOG_INFO ("FEC Block " << m_currentBlockId << " full (K=" << m_fecK
                       << (m_isRetransmitting ? ", triggered by retransmit" : "") << "), will send repairs.");
          // [項目2] 預先 RS 編碼此 Block 的所有 Repair Symbols
          RsEncodeBlock (m_currentBlockId);
          needSendRepairs = true;
          m_currentBlockIdx = 0;
          m_currentBlockId++;  // Block 結束後才遞增 Block ID
        }
    }
  
  QuicHeader head;

  if (m_socketState == CONNECTING_SVR)
    {
      m_connected = true;
      head = QuicHeader::CreateHandshake (m_connectionId, m_vers,
                                          packetNumber);
    }
  else if (m_socketState == CONNECTING_CLT)
    {
      head = QuicHeader::CreateInitial (m_connectionId, m_vers, packetNumber);
    }
  else if (m_socketState == OPEN)
    {
      if (!m_connected and !m_quicl4->Is0RTTHandshakeAllowed ())
        {
          m_connected = true;
          head = QuicHeader::CreateHandshake (m_connectionId, m_vers,
                                              packetNumber);
        }
      else if (!m_connected and m_quicl4->Is0RTTHandshakeAllowed ())
        {
          head = QuicHeader::Create0RTT (m_connectionId, m_vers,
                                         packetNumber);
          m_connected = true;
          m_keyPhase == QuicHeader::PHASE_ONE ? m_keyPhase =
            QuicHeader::PHASE_ZERO :
            m_keyPhase =
              QuicHeader::PHASE_ONE;
        }
      else
        {
          head = QuicHeader::CreateShort (m_connectionId, packetNumber,
                                          !m_omit_connection_id, m_keyPhase);
        }
    }
  else
    {
      // 0 bytes sent - the socket is closed!
      return 0;
    }

  NS_LOG_INFO ("SendDataPacket of size " << p->GetSize ());
  m_quicl4->SendPacket (this, p, head);
  //FEC統計
  g_totalWireBytesSent += (p->GetSize () + 28);
  
  m_txTrace (p, head, this);
  NotifyDataSent (sz);

  // === FEC: 在 Source Packet 真正發送之後，發送 Repair Packets ===
  if (needSendRepairs)
    {
      NS_LOG_INFO ("Block complete: Sending Repair Packets for Block " << repairBlockId);
      
      // 直接發送所有 Repair Packets
      // 因為 Source 封包的 interval 已經預留了 FEC overhead 的時間
      // (interval = simDuration / totalPackets，其中 totalPackets 包含 Repair)
      // 所以在傳輸期間有足夠的頻寬餘量來發送 Repair
      for (uint32_t i = 0; i < m_fecP; ++i)
        {
          SendSingleRepairPacket (repairBlockId, i);
        }
    }
  // ================================================================

  if (!m_quicCongestionControlLegacy)
    {
      DynamicCast<QuicCongestionOps> (m_congestionControl)->OnPacketSent (
        m_tcb, packetNumber, isAckOnly);
    }
  if (!isAckOnly)
    {
      SetReTxTimeout ();
    }
  return sz;
}

void
QuicSocketBase::SetReTxTimeout ()
{
  //TODO check for special packets
  NS_LOG_FUNCTION (this);

  // Don't arm the alarm if there are no packets with retransmittable data in flight.
  //if (numRetransmittablePacketsOutstanding == 0)
  if (false)
    {
      m_tcb->m_lossDetectionAlarm.Cancel ();
      return;
    }
  
  if (m_tcb->m_kUsingTimeLossDetection)
    {
      m_tcb->m_lossTime = Simulator::Now() + m_tcb->m_kTimeReorderingFraction * m_tcb->m_smoothedRtt;
    }

  Time alarmDuration;
  // Handshake packets are outstanding
  if (m_socketState == CONNECTING_CLT || m_socketState == CONNECTING_SVR)
    {
      NS_LOG_INFO ("Connecting, set alarm");
      // Handshake retransmission alarm.
      if (m_tcb->m_smoothedRtt.IsZero())
        {
          alarmDuration = 2 * m_tcb->m_kDefaultInitialRtt;
        }
      else
        {
          alarmDuration = 2 * m_tcb->m_smoothedRtt;
        }
      alarmDuration = std::max (alarmDuration + m_tcb->m_maxAckDelay,
                                m_tcb->m_kMinTLPTimeout);
      alarmDuration = alarmDuration * (2 ^ m_tcb->m_handshakeCount);
      m_tcb->m_alarmType = 0;
    }
  else if (m_tcb->m_lossTime != Time(0))
    {
      NS_LOG_INFO ("Early retransmit timer");
      // Early retransmit timer or time loss detection.
      alarmDuration = m_tcb->m_lossTime - m_tcb->m_timeOfLastSentPacket;
      m_tcb->m_alarmType = 1;
    }
  else if (m_tcb->m_tlpCount < m_tcb->m_kMaxTLPs)
    {
      NS_LOG_LOGIC ("m_tcb->m_tlpCount < m_tcb->m_kMaxTLPs");
      // Tail Loss Probe
      alarmDuration = std::max (
          (3 / 2) * m_tcb->m_smoothedRtt + m_tcb->m_maxAckDelay,
          m_tcb->m_kMinTLPTimeout);
      m_tcb->m_alarmType = 2;
    }
  else
    {
      NS_LOG_LOGIC ("RTO");
      alarmDuration = m_tcb->m_smoothedRtt + 4 * m_tcb->m_rttVar
        + m_tcb->m_maxAckDelay;
      alarmDuration = std::max (alarmDuration, m_tcb->m_kMinRTOTimeout);
      alarmDuration = alarmDuration * (2 ^ m_tcb->m_rtoCount);
      m_tcb->m_alarmType = 3;
    }
  NS_LOG_INFO ("Schedule ReTxTimeout at time " << Simulator::Now ().GetSeconds () << " to expire at time " << (Simulator::Now () + alarmDuration).GetSeconds ());
  NS_LOG_INFO ("Alarm after " << alarmDuration.GetSeconds () << " seconds");
  m_tcb->m_lossDetectionAlarm = Simulator::Schedule (alarmDuration,
                                                     &QuicSocketBase::ReTxTimeout, this);
  m_tcb->m_nextAlarmTrigger = Simulator::Now () + alarmDuration;
}

void
QuicSocketBase::DoRetransmit (std::vector<QuicSocketTxItem*> lostPackets)
{
  NS_LOG_FUNCTION (this);
  
  // 如果重傳被關閉，直接返回（不執行任何重傳）
  if (m_disableRetransmission)
    {
      NS_LOG_INFO ("Retransmission disabled - skipping retransmit for " << lostPackets.size() << " lost packets");
      return;
    }
    
  // Get packets to retransmit
  SequenceNumber32 next = ++m_tcb->m_nextTxSequence;
  uint32_t toRetx = m_txBuffer->Retransmission (next);
  NS_LOG_DEBUG ("Send the retransmitted frame");
  uint32_t win = AvailableWindow ();
  uint32_t connWin = ConnectionWindow ();
  uint32_t bytesInFlight = BytesInFlight ();
  NS_LOG_DEBUG (
    "BEFORE Available Window " << win
                               << " Connection RWnd " << connWin
                               << " BytesInFlight " << bytesInFlight
                               << " BufferedSize " << m_txBuffer->AppSize ()
                               << " MaxPacketSize " << GetSegSize ());

  // [項目1] 設定重傳旗標：重傳封包不計入 m_sourcePacketSent，使 PLR 統計正確
  m_isRetransmitting = true;
  NS_LOG_INFO ("Retransmitted packet, next sequence number " << m_tcb->m_nextTxSequence);
  SendDataPacket (next, toRetx, m_connected);
  m_isRetransmitting = false;
}

void
QuicSocketBase::ReTxTimeout ()
{
  if (Simulator::Now () < m_tcb->m_nextAlarmTrigger)
    {
      NS_LOG_INFO ("Canceled alarm");
      return;
    }
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO ("ReTxTimeout Expired at time " << Simulator::Now ().GetSeconds ());
  // Handshake packets are outstanding)
  if (m_tcb->m_alarmType == 0 && (m_socketState == CONNECTING_CLT || m_socketState == CONNECTING_SVR))
    {
      // Handshake retransmission alarm.
      // 注意：握手階段的重傳不受 m_disableRetransmission 影響，以確保連線能建立
      //TODO retransmit handshake packets
      //RetransmitAllHandshakePackets();
      m_tcb->m_handshakeCount++;
    }
  else if (m_tcb->m_alarmType == 1 && m_tcb->m_lossTime != Time(0))
    {
      std::vector<QuicSocketTxItem*> lostPackets = m_txBuffer->DetectLostPackets ();
      NS_LOG_INFO ("RTO triggered: early retransmit");
      // Early retransmit or Time Loss Detection.
      if (m_quicCongestionControlLegacy)
        {
          // TCP early retransmit logic [RFC 5827]: enter recovery (RFC 6675, Sec. 5)
          if (m_tcb->m_congState != TcpSocketState::CA_RECOVERY)
            {
              m_tcb->m_congState = TcpSocketState::CA_RECOVERY;
              m_tcb->m_cWnd = m_tcb->m_ssThresh;
              m_tcb->m_endOfRecovery = m_tcb->m_highTxMark;
              m_congestionControl->CongestionStateSet (
                m_tcb, TcpSocketState::CA_RECOVERY);
              m_tcb->m_ssThresh = m_congestionControl->GetSsThresh (
                  m_tcb, BytesInFlight ());
            }
        }
      else
        {
          Ptr<QuicCongestionOps> cc = dynamic_cast<QuicCongestionOps*> (&(*m_congestionControl));
          cc->OnPacketsLost (m_tcb, lostPackets);
        }
      // Retransmit all lost packets immediately
      DoRetransmit (lostPackets);
    }
  else if (m_tcb->m_alarmType == 2 && m_tcb->m_tlpCount < m_tcb->m_kMaxTLPs)
    {
      // Tail Loss Probe. Send one new data packet, do not retransmit - IETF Draft QUIC Recovery, Sec. 4.3.2
      // 如果重傳被關閉，跳過 TLP
      if (m_disableRetransmission)
        {
          NS_LOG_INFO ("Retransmission disabled - skipping TLP");
          m_tcb->m_tlpCount++;
          return;
        }
      SequenceNumber32 next = ++m_tcb->m_nextTxSequence;
      NS_LOG_INFO ("TLP triggered");
      uint32_t s = std::min (ConnectionWindow (), GetSegSize ());
      SendDataPacket (next, s, m_connected);
      m_tcb->m_tlpCount++;
    }
  else if (m_tcb->m_alarmType == 3)
    {
      // RTO.
      // 如果重傳被關閉，跳過 RTO 探測包
      if (m_disableRetransmission)
        {
          NS_LOG_INFO ("Retransmission disabled - skipping RTO probes");
          m_tcb->m_rtoCount++;
          return;
        }
      if (m_tcb->m_rtoCount == 0)
        {
          m_tcb->m_largestSentBeforeRto = m_tcb->m_highTxMark;
        }
      // RTO. Send two new data packets, do not retransmit - IETF Draft QUIC Recovery, Sec. 4.3.3
      NS_LOG_INFO ("RTO triggered");
      SequenceNumber32 next = ++m_tcb->m_nextTxSequence;
      uint32_t s = std::min (AvailableWindow (), GetSegSize ());
      SendDataPacket (next, s, m_connected);
      next = ++m_tcb->m_nextTxSequence;

      s = std::min (AvailableWindow (), GetSegSize ());
      SendDataPacket (next, s, m_connected);

      m_tcb->m_rtoCount++;
    }
}

uint32_t
QuicSocketBase::AvailableWindow () const
{
  NS_LOG_FUNCTION (this);

  NS_LOG_DEBUG ("m_max_data " << m_max_data << " m_tcb->m_cWnd.Get () " << m_tcb->m_cWnd.Get ());
  uint32_t win = std::min (m_max_data, m_tcb->m_cWnd.Get ());   // Number of bytes allowed to be outstanding
  uint32_t inflight = BytesInFlight ();   // Number of outstanding bytes

  if (inflight > win)
    {
      NS_LOG_INFO (
        "InFlight=" << inflight << ", Win=" << win << " availWin=0");
      return 0;
    }

  NS_LOG_INFO (
    "InFlight=" << inflight << ", Win=" << win << " availWin=" << win - inflight);
  return win - inflight;

}

uint32_t
QuicSocketBase::ConnectionWindow () const
{
  NS_LOG_FUNCTION (this);

  uint32_t inFlight = BytesInFlight ();

  NS_LOG_INFO (
    "Returning calculated Connection: MaxData " << m_max_data << " InFlight: " << inFlight);

  return (inFlight > m_max_data) ? 0 : m_max_data - inFlight;
}

uint32_t
QuicSocketBase::BytesInFlight () const
{
  NS_LOG_FUNCTION (this);

  uint32_t bytesInFlight = m_txBuffer->BytesInFlight ();

  NS_LOG_INFO ("Returning calculated bytesInFlight: " << bytesInFlight);
  return bytesInFlight;
}

/* Inherit from Socket class: In QuicSocketBase, it is same as Send() call */
int
QuicSocketBase::SendTo (Ptr<Packet> p, uint32_t flags, const Address &address)
{
  NS_LOG_FUNCTION (this);

  return Send (p, flags);
}

/* Inherit from Socket class: Return data to upper-layer application. Parameter flags
 is not used. Data is returned as a packet of size no larger than maxSize */
Ptr<Packet>
QuicSocketBase::Recv (uint32_t maxSize, uint32_t flags)
{
  NS_LOG_FUNCTION (this);
  NS_ABORT_MSG_IF (flags,
                   "use of flags is not supported in QuicSocketBase::Recv()");

  if (m_rxBuffer->Size () == 0 && m_socketState == CLOSING)
    {
      return Create<Packet> ();
    }
  Ptr<Packet> outPacket = m_rxBuffer->Extract (maxSize);
  return outPacket;
}

/* Inherit from Socket class: Recv and return the remote's address */
Ptr<Packet>
QuicSocketBase::RecvFrom (uint32_t maxSize, uint32_t flags,
                          Address &fromAddress)
{
  NS_LOG_FUNCTION (this);

  Ptr<Packet> packet = m_rxBuffer->Extract (maxSize);

  if (packet != nullptr && packet->GetSize () != 0)
    {
      if (m_endPoint != nullptr)
        {          
          fromAddress = InetSocketAddress (m_endPoint->GetPeerAddress (), m_endPoint->GetPeerPort ());
        }
      else if (m_endPoint6 != nullptr)
        {
          fromAddress = Inet6SocketAddress (m_endPoint6->GetPeerAddress (), m_endPoint6->GetPeerPort ());
        }
      else
        {
          fromAddress = InetSocketAddress (Ipv4Address::GetZero (), 0);
        }
    }

  return packet;
}

int
QuicSocketBase::Close (void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO (this << " Close at time " << Simulator::Now ().GetSeconds ());

  NS_LOG_INFO ("[FEC Close] m_sourcePacketSent=" << m_sourcePacketSent
               << " m_currentBlockId=" << m_currentBlockId
               << " m_currentBlockIdx=" << m_currentBlockIdx);

  // === FEC: 發送最後一個不完整 Block 的 Repair Packets ===
  if (m_enableFec && m_currentBlockIdx > 0 && m_sourcePacketSent > 0)
    {
      NS_LOG_INFO ("FEC: Sending Repair for last incomplete Block " << m_currentBlockId 
                   << " (has " << m_currentBlockIdx << "/" << m_fecK << " sources)");
      
      // 發送 Repair Packets（數量與已發送的 Source 成比例，但至少發送 m_fecP 個以確保冗餘）
      for (uint32_t i = 0; i < m_fecP; ++i)
        {
          SendSingleRepairPacket (m_currentBlockId, i);
        }
    }
  // =========================================================

  m_receivedTransportParameters = false;

  if (m_idleTimeoutEvent.IsRunning () and m_socketState != IDLE
      and m_socketState != CLOSING)   //Connection Close from application signal
    {
      SetState (CLOSING);
      m_drainingPeriodEvent.Cancel ();
      m_idleTimeoutEvent.Cancel ();
      NS_LOG_LOGIC (
        this << " Close Schedule DoClose at time " << Simulator::Now ().GetSeconds () << " to expire at time " << (Simulator::Now () + m_drainingPeriodTimeout.Get ()).GetSeconds ());
      m_drainingPeriodEvent = Simulator::Schedule (m_drainingPeriodTimeout,
                                                   &QuicSocketBase::DoClose,
                                                   this);
      SendConnectionClosePacket (0, "Scheduled connection close - no error");
    }
  else if (m_idleTimeoutEvent.IsExpired () and m_socketState != CLOSING
           and m_socketState != IDLE and m_socketState != LISTENING) //Connection Close due to Idle Period termination
    {
      SetState (CLOSING);
      m_drainingPeriodEvent.Cancel ();
      NS_LOG_LOGIC (
        this << " Close Schedule DoClose at time " << Simulator::Now ().GetSeconds () << " to expire at time " << (Simulator::Now () + m_drainingPeriodTimeout.Get ()).GetSeconds ());
      m_drainingPeriodEvent = Simulator::Schedule (m_drainingPeriodTimeout,
                                                   &QuicSocketBase::DoClose,
                                                   this);
    }
  else if (m_idleTimeoutEvent.IsExpired ()
           and m_drainingPeriodEvent.IsExpired () and m_socketState != CLOSING
           and m_socketState != IDLE) //close last listening sockets
    {
      NS_LOG_LOGIC (this << " Closing listening socket");
      DoClose ();
    }
  else if (m_idleTimeoutEvent.IsExpired ()
           and m_drainingPeriodEvent.IsExpired () and m_socketState == IDLE)
    {
      NS_LOG_LOGIC (this << " Has already been closed");
    }

  return 0;
}

/* Send a CONNECTION_CLOSE frame */
uint32_t
QuicSocketBase::SendConnectionClosePacket (uint16_t errorCode, std::string phrase)
{
  NS_LOG_FUNCTION (this);

  Ptr<Packet> p = Create<Packet> ();
  SequenceNumber32 packetNumber = ++m_tcb->m_nextTxSequence;

  QuicSubheader qsb = QuicSubheader::CreateConnectionClose (errorCode, phrase.c_str ());
  p->AddHeader (qsb);


  QuicHeader head;

  head = QuicHeader::CreateShort (m_connectionId, packetNumber,
                                  !m_omit_connection_id, m_keyPhase);


  NS_LOG_DEBUG ("Send Connection Close packet with header " << head);
  m_quicl4->SendPacket (this, p, head);
  m_txTrace (p, head, this);

  return 0;
}

/* Inherit from Socket class: Signal a termination of send */
int
QuicSocketBase::ShutdownSend (void)
{
  NS_LOG_FUNCTION (this);



  return 0;
}

/* Inherit from Socket class: Signal a termination of receive */
int
QuicSocketBase::ShutdownRecv (void)
{
  NS_LOG_FUNCTION (this);

  return 0;
}

void
QuicSocketBase::SetNode (Ptr<Node> node)
{
//NS_LOG_FUNCTION (this);

  m_node = node;
}

Ptr<Node>
QuicSocketBase::GetNode (void) const
{
//NS_LOG_FUNCTION_NOARGS ();

  return m_node;
}

/* Inherit from Socket class: Return local address:port */
int
QuicSocketBase::GetSockName (Address &address) const
{
  NS_LOG_FUNCTION (this);

  return m_quicl4->GetSockName (this, address);
}

int
QuicSocketBase::GetPeerName (Address &address) const
{
  NS_LOG_FUNCTION (this);

  return m_quicl4->GetPeerName (this, address);
}

/* Inherit from Socket class: Get the max number of bytes an app can send */
uint32_t
QuicSocketBase::GetTxAvailable (void) const
{
  NS_LOG_FUNCTION (this);

  return m_txBuffer->Available ();
}

/* Inherit from Socket class: Get the max number of bytes an app can read */
uint32_t
QuicSocketBase::GetRxAvailable (void) const
{
  NS_LOG_FUNCTION (this);

  return m_rxBuffer->Available ();
}

/* Inherit from Socket class: Returns error code */
enum Socket::SocketErrno
QuicSocketBase::GetErrno (void) const
{
  return m_errno;
}

/* Inherit from Socket class: Returns socket type, NS3_SOCK_STREAM */
enum Socket::SocketType
QuicSocketBase::GetSocketType (void) const
{
  return NS3_SOCK_STREAM;
}

//////////////////////////////////////////////////////////////////////////////////////

/* Clean up after Bind. Set up callback functions in the end-point. */
int
QuicSocketBase::SetupCallback (void)
{
  NS_LOG_FUNCTION (this);

  if (m_quicl4 == 0)
    {
      return -1;
    }
  else
    {
      m_quicl4->SetRecvCallback (
        MakeCallback (&QuicSocketBase::ReceivedData, this), this);
    }

  return 0;
}

int
QuicSocketBase::AppendingRx (Ptr<Packet> frame, Address &address)
{

  NS_LOG_FUNCTION (this);

  if (!m_rxBuffer->Add (frame))
    {
      // Insert failed: No data or RX buffer full
      NS_LOG_INFO ("Dropping packet due to full RX buffer");
      return 0;
    }
  else
    {
      // [項目1] 追蹤 stream 層收到的 bytes（含重傳，用於計算真實 Post-FEC PLR）
      m_streamBytesReceived += frame->GetSize ();
      NS_LOG_INFO ("Notify Data Recv");
      NotifyDataRecv ();   // trigger the application method
    }

  return frame->GetSize ();
}

void
QuicSocketBase::SetQuicL4 (Ptr<QuicL4Protocol> quic)
{
  NS_LOG_FUNCTION (this);

  m_quicl4 = quic;
}

void
QuicSocketBase::SetConnectionId (uint64_t connectionId)
{
  NS_LOG_FUNCTION_NOARGS ();

  m_connectionId = connectionId;
}

uint64_t
QuicSocketBase::GetConnectionId (void) const
{
  NS_LOG_FUNCTION_NOARGS ();

  return m_connectionId;
}

void
QuicSocketBase::SetVersion (uint32_t version)
{
  NS_LOG_FUNCTION (this);

  m_vers = version;
  return;
}

//////////////////////////////////////////////////////////////////////////////////////

bool
QuicSocketBase::SetAllowBroadcast (bool allowBroadcast)
{
  NS_LOG_FUNCTION (this);

  return (!allowBroadcast);
}

bool
QuicSocketBase::GetAllowBroadcast (void) const
{
  return false;
}

Ptr<QuicL5Protocol>
QuicSocketBase::CreateStreamController ()
{
  NS_LOG_FUNCTION (this);

  Ptr<QuicL5Protocol> quicl5 = CreateObject<QuicL5Protocol> ();

  quicl5->SetSocket (this);
  quicl5->SetNode (m_node);
  quicl5->SetConnectionId (m_connectionId);

  return quicl5;
}

void
QuicSocketBase::SendInitialHandshake (uint8_t type,
                                      const QuicHeader &quicHeader,
                                      Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << m_vers);

  if (type == QuicHeader::VERSION_NEGOTIATION)
    {
      NS_LOG_INFO ("Create VERSION_NEGOTIATION");
      m_receivedTransportParameters = false;
      m_couldContainTransportParameters = true;

      std::vector<uint32_t> supportedVersions;
      supportedVersions.push_back (QUIC_VERSION);
      supportedVersions.push_back (QUIC_VERSION_DRAFT_10);
      supportedVersions.push_back (QUIC_VERSION_NS3_IMPL);

      uint8_t *buffer = new uint8_t[4 * supportedVersions.size ()];

      Ptr<Packet> payload = Create<Packet> (buffer,
                                            4 * supportedVersions.size ());

      for (uint8_t i = 0; i < (uint8_t) supportedVersions.size (); i++)
        {

          buffer[4 * i] = (supportedVersions[i]);
          buffer[4 * i + 1] = (supportedVersions[i] >> 8);
          buffer[4 * i + 2] = (supportedVersions[i] >> 16);
          buffer[4 * i + 3] = (supportedVersions[i] >> 24);
          //NS_LOG_INFO(" " << (uint64_t) buffer[4*i] << " " << (uint64_t)buffer[4*i+1] << " " << (uint64_t)buffer[4*i+2] << " " << (uint64_t)buffer[4*i+3] );

        }

      Ptr<Packet> p = Create<Packet> (buffer, 4 * supportedVersions.size ());
      QuicHeader head = QuicHeader::CreateVersionNegotiation (
          quicHeader.GetConnectionId (),
          QUIC_VERSION_NEGOTIATION,
          supportedVersions);

      // Set initial congestion window and Ssthresh
      m_tcb->m_cWnd = m_tcb->m_initialCWnd;
      m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;

      m_quicl4->SendPacket (this, p, head);
      m_txTrace (p, head, this);
      NotifyDataSent (p->GetSize ());

    }
  else if (type == QuicHeader::INITIAL)
    {
      // Set initial congestion window and Ssthresh
      m_tcb->m_cWnd = m_tcb->m_initialCWnd;
      m_tcb->m_ssThresh = m_tcb->m_initialSsThresh;

      NS_LOG_INFO ("Create INITIAL");
      Ptr<Packet> p = Create<Packet> ();
      p->AddHeader (OnSendingTransportParameters ());
      // the RFC says that
      // "Clients MUST ensure that the first Initial packet they
      // send is sent in a UDP datagram that is at least 1200 octets."
      Ptr<Packet> payload = Create<Packet> (
        GetInitialPacketSize() - p->GetSize ());
      p->AddAtEnd (payload);

      m_quicl5->DispatchSend (p, 0);

    }
  else if (type == QuicHeader::RETRY)
    {
      NS_LOG_INFO ("Create RETRY");
      Ptr<Packet> p = Create<Packet> ();
      p->AddHeader (OnSendingTransportParameters ());
      Ptr<Packet> payload = Create<Packet> (
          GetInitialPacketSize() - p->GetSize ());
      p->AddAtEnd (payload);

      m_quicl5->DispatchSend (p, 0);
    }
  else if (type == QuicHeader::HANDSHAKE)
    {
      NS_LOG_INFO ("Create HANDSHAKE");
      Ptr<Packet> p = Create<Packet> ();
      if (m_socketState == CONNECTING_SVR)
        {
          p->AddHeader (OnSendingTransportParameters ());
        }

      Ptr<Packet> payload = Create<Packet> (
          GetInitialPacketSize() - p->GetSize ());
      p->AddAtEnd (payload);

      m_quicl5->DispatchSend (p, 0);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
    }
  else if (type == QuicHeader::ZRTT_PROTECTED)
    {
      NS_LOG_INFO ("Create ZRTT_PROTECTED");
      Ptr<Packet> p = Create<Packet> ();
      p->AddHeader (OnSendingTransportParameters ());

      m_quicl5->DispatchSend (p, 0);

    }
  else
    {

      NS_LOG_INFO ("Wrong Handshake Type");

      return;

    }
}

void
QuicSocketBase::OnReceivedFrame (QuicSubheader &sub)
{
  NS_LOG_FUNCTION (this << (uint64_t)sub.GetFrameType ());

  uint8_t frameType = sub.GetFrameType ();

  switch (frameType)
    {

    case QuicSubheader::ACK:
      NS_LOG_INFO ("Received ACK frame");
      OnReceivedAckFrame (sub);
      break;

    case QuicSubheader::CONNECTION_CLOSE:
      NS_LOG_INFO ("Received CONNECTION_CLOSE frame");
      Close ();
      break;

    case QuicSubheader::APPLICATION_CLOSE:
      NS_LOG_INFO ("Received APPLICATION_CLOSE frame");
      DoClose ();
      break;

    case QuicSubheader::PADDING:
      NS_LOG_INFO ("Received PADDING frame");
      // no need to do anything
      break;

    case QuicSubheader::MAX_DATA:
      // set the maximum amount of data that can be sent
      // on this connection
      NS_LOG_INFO ("Received MAX_DATA frame");
      SetConnectionMaxData (sub.GetMaxData ());
      break;

    case QuicSubheader::MAX_STREAM_ID:
      // TODO update the maximum stream ID
      NS_LOG_INFO ("Received MAX_STREAM_ID frame");
      break;

    case QuicSubheader::PING:
      // TODO
      NS_LOG_INFO ("Received PING frame");
      break;

    case QuicSubheader::BLOCKED:
      // TODO
      NS_LOG_INFO ("Received BLOCKED frame");
      break;

    case QuicSubheader::STREAM_ID_BLOCKED:
      // TODO
      NS_LOG_INFO ("Received STREAM_ID_BLOCKED frame");
      break;

    case QuicSubheader::NEW_CONNECTION_ID:
      // TODO
      NS_LOG_INFO ("Received NEW_CONNECTION_ID frame");
      break;

    case QuicSubheader::PATH_CHALLENGE:
      // TODO reply with a PATH_RESPONSE with the same value
      // as that carried by the PATH_CHALLENGE
      NS_LOG_INFO ("Received PATH_CHALLENGE frame");
      break;

    case QuicSubheader::PATH_RESPONSE:
      // TODO check if it matches what was sent in a PATH_CHALLENGE
      // otherwise abort with a UNSOLICITED_PATH_RESPONSE error
      NS_LOG_INFO ("Received PATH_RESPONSE frame");
      break;
    
    //FEC  
    case QuicSubheader::FEC_TAG:
      NS_LOG_INFO ("Received FEC_TAG frame");
      ProcessFecTag (sub);
      break;

    case QuicSubheader::FEC_REPAIR:
      NS_LOG_INFO ("Received FEC_REPAIR frame");
      ProcessFecRepair (sub);
      break;

    case QuicSubheader::FEC_ACK:
      // [項目3] FEC_ACK 接收處理（發送端收到接收端的恢復報告）
      m_fecAckReceivedCount++;
      NS_LOG_INFO ("Received FEC_ACK #" << m_fecAckReceivedCount
                   << " RestoredPkts=" << sub.GetFecRestoredPackets ()
                   << " RestoredBytes=" << sub.GetFecRestoredBytes ()
                   << " LatestRestoredPN=" << sub.GetFecLatestRestoredPn ());
      // 注意：重傳佇列的清理由正常 ACK 機制（MaybeQueueAck）負責，
      // FEC_ACK 主要用於統計與未來的 Adaptive FEC 調整。
      break;

    default:
      AbortConnection (
        QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
        "Received Corrupted Frame");
      return;
    }

}

Ptr<Packet>
QuicSocketBase::OnSendingAckFrame ()
{
  NS_LOG_FUNCTION (this);

  NS_ABORT_MSG_IF (m_receivedPacketNumbers.empty (),
                   " Sending Ack Frame without packets to acknowledge");

//m_delAckEvent.Cancel();
//m_delAckCount = 0;

  NS_LOG_INFO ("Attach an ACK frame to the packet");

  std::sort (m_receivedPacketNumbers.begin (), m_receivedPacketNumbers.end (),
             std::greater<SequenceNumber32> ());

  SequenceNumber32 largestAcknowledged = *(m_receivedPacketNumbers.begin ());

  uint32_t ackBlockCount = 0;
  std::vector<uint32_t> additionalAckBlocks;
  std::vector<uint32_t> gaps;

  std::vector<SequenceNumber32>::const_iterator curr_rec_it =
    m_receivedPacketNumbers.begin ();
  std::vector<SequenceNumber32>::const_iterator next_rec_it =
    m_receivedPacketNumbers.begin () + 1;

  for (; next_rec_it != m_receivedPacketNumbers.end ();
       ++curr_rec_it, ++next_rec_it)
    {

      if (((*curr_rec_it) - (*next_rec_it) - 1 > 0)
          and ((*curr_rec_it) != (*next_rec_it)))
        {
          //std::clog << "curr " << (*curr_rec_it) << " next " << (*next_rec_it) << " ";
          additionalAckBlocks.push_back ((*next_rec_it).GetValue ());
          gaps.push_back ((*curr_rec_it).GetValue () - 1);
          ackBlockCount++;
        }
      // Limit the number of gaps that are sent in an ACK (older packets have already been retransmitted)
      if (ackBlockCount >= m_maxTrackedGaps) {
          break;
      }
    }
  

  Time delay = Simulator::Now() - m_lastReceived;
  uint64_t ack_delay = delay.GetMicroSeconds();
  QuicSubheader sub = QuicSubheader::CreateAck (
      largestAcknowledged.GetValue (), ack_delay, largestAcknowledged.GetValue (),
      gaps, additionalAckBlocks);
  QuicSubheader maxData = QuicSubheader::CreateMaxData(m_quicl5->GetMaxData());

  Ptr<Packet> ackFrame = Create<Packet> ();
  ackFrame->AddHeader (sub);
  ackFrame->AddHeader(maxData);
  return ackFrame;
}

void
QuicSocketBase::OnReceivedAckFrame (QuicSubheader &sub)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO ("Process ACK");

  uint32_t previousWindow = m_txBuffer->BytesInFlight ();
  
  std::vector<uint32_t> additionalAckBlocks = sub.GetAdditionalAckBlocks ();
  std::vector<uint32_t> gaps = sub.GetGaps ();
  uint32_t largestAcknowledged = sub.GetLargestAcknowledged ();
  m_tcb->m_lastAckedSeq = largestAcknowledged;
  uint32_t ackBlockCount = sub.GetAckBlockCount ();

  NS_ABORT_MSG_IF (
    ackBlockCount != additionalAckBlocks.size ()
    and ackBlockCount != gaps.size (),
    "Received Corrupted Ack Frame.");

  std::vector<QuicSocketTxItem*> ackedPackets = m_txBuffer->OnAckUpdate (
      m_tcb, largestAcknowledged, additionalAckBlocks, gaps);

  // Count newly acked bytes
  uint32_t ackedBytes = previousWindow - m_txBuffer->BytesInFlight ();

  // RTO packet acknowledged - IETF Draft QUIC Recovery, Sec. 4.3.3
  if (m_tcb->m_rtoCount > 0)
    {
      // Packets after the RTO have been acknowledged
      if (m_tcb->m_largestSentBeforeRto.GetValue () < largestAcknowledged)
        {

          uint32_t newPackets = (largestAcknowledged
                                 - m_tcb->m_largestSentBeforeRto.GetValue ()) / GetSegSize ();
          uint32_t inFlightBeforeRto = m_txBuffer->BytesInFlight ();
          m_txBuffer->ResetSentList (newPackets);
          std::vector<QuicSocketTxItem*> lostPackets =
            m_txBuffer->DetectLostPackets ();
          if (m_quicCongestionControlLegacy && !lostPackets.empty ())
            {
              // Reset congestion window and go into loss mode
              m_tcb->m_cWnd = m_tcb->m_kMinimumWindow;
              m_tcb->m_endOfRecovery = m_tcb->m_highTxMark;
              m_tcb->m_ssThresh = m_congestionControl->GetSsThresh (
                  m_tcb, inFlightBeforeRto);
              m_tcb->m_congState = TcpSocketState::CA_LOSS;
              m_congestionControl->CongestionStateSet (
                m_tcb, TcpSocketState::CA_LOSS);
            }
        }
      else
        {
          m_tcb->m_rtoCount = 0;
        }
    }

  // Tail loss probe packet acknowledged - IETF Draft QUIC Recovery, Sec. 4.3.2
  if (m_tcb->m_tlpCount > 0 && !ackedPackets.empty ())
    {
      m_tcb->m_tlpCount = 0;
    }

  // Find lost packets
  std::vector<QuicSocketTxItem*> lostPackets =
    m_txBuffer->DetectLostPackets ();
  // Recover from losses
  if (!lostPackets.empty ())
    {
      if (m_quicCongestionControlLegacy)
        {
          //Enter recovery (RFC 6675, Sec. 5)
          if (m_tcb->m_congState != TcpSocketState::CA_RECOVERY)
            {
              m_tcb->m_congState = TcpSocketState::CA_RECOVERY;
              m_tcb->m_endOfRecovery = m_tcb->m_highTxMark;
              m_congestionControl->CongestionStateSet (
                m_tcb, TcpSocketState::CA_RECOVERY);
              m_tcb->m_ssThresh = m_congestionControl->GetSsThresh (
                  m_tcb, BytesInFlight ());
              m_tcb->m_cWnd = m_tcb->m_ssThresh;
            }
          NS_ASSERT (m_tcb->m_congState == TcpSocketState::CA_RECOVERY);
        }
      else
        {
          DynamicCast<QuicCongestionOps> (m_congestionControl)->OnPacketsLost (
            m_tcb, lostPackets);
        }
      DoRetransmit (lostPackets);
    }
  else if (ackedBytes > 0)
    {
      if (!m_quicCongestionControlLegacy)
        {
          NS_LOG_INFO ("Update the variables in the congestion control (QUIC)");
          // Process the ACK
          DynamicCast<QuicCongestionOps> (m_congestionControl)->OnAckReceived (
            m_tcb, sub, ackedPackets);
          m_lastRtt = m_tcb->m_lastRtt;
        }
      else
        {
          uint32_t ackedSegments = ackedBytes / GetSegSize ();
          
          NS_LOG_INFO ("Update the variables in the congestion control (legacy), ackedBytes "
                       << ackedBytes << " ackedSegments " << ackedSegments);
          // new acks are ordered from the highest packet number to the smalles
          QuicSocketTxItem* lastAcked = ackedPackets.at (0);

          NS_LOG_LOGIC ("Updating RTT estimate");
          // If the largest acked is newly acked, update the RTT.
          if (lastAcked->m_packetNumber >= m_tcb->m_largestAckedPacket)
            {
              Time ackDelay = MicroSeconds(sub.GetAckDelay());
              m_tcb->m_lastRtt = Now () - lastAcked->m_lastSent - ackDelay;
              m_lastRtt = m_tcb->m_lastRtt;
            }
          if (m_tcb->m_congState != TcpSocketState::CA_RECOVERY
              && m_tcb->m_congState != TcpSocketState::CA_LOSS)
            {
              // Increase the congestion window
              m_congestionControl->PktsAcked (m_tcb, ackedSegments,
                                              m_tcb->m_lastRtt);
              m_congestionControl->IncreaseWindow (m_tcb, ackedSegments);
            }
          else
            {
              if (m_tcb->m_endOfRecovery.GetValue () > largestAcknowledged)
                {
                  m_congestionControl->PktsAcked (m_tcb, ackedSegments,
                                                  m_tcb->m_lastRtt);
                  m_congestionControl->IncreaseWindow (m_tcb, ackedSegments);
                }
              else
                {
                  m_tcb->m_congState = TcpSocketState::CA_OPEN;
                  m_congestionControl->PktsAcked (m_tcb, ackedSegments, m_tcb->m_lastRtt);
                  m_congestionControl->CongestionStateSet (m_tcb, TcpSocketState::CA_OPEN);
                }
            }
        }
    }
  else
    {
      NS_LOG_INFO ("Received an ACK to ack an ACK");
    }

  // notify the application that more data can be sent
  if (GetTxAvailable () > 0)
    {
      NotifySend (GetTxAvailable ());
    }

  // try to send more data
  SendPendingData (m_connected);

  // Compute timers
  SetReTxTimeout ();
}

QuicTransportParameters
QuicSocketBase::OnSendingTransportParameters ()
{
  NS_LOG_FUNCTION (this);

  QuicTransportParameters transportParameters;
  transportParameters = transportParameters.CreateTransportParameters (
      m_initial_max_stream_data, m_max_data, m_initial_max_stream_id_bidi,
      (uint16_t) m_idleTimeout.Get ().GetSeconds (),
      (uint8_t) m_omit_connection_id, m_tcb->m_segmentSize,
      m_ack_delay_exponent, m_initial_max_stream_id_uni);

  return transportParameters;
}

void
QuicSocketBase::OnReceivedTransportParameters (
  QuicTransportParameters transportParameters)
{
  NS_LOG_FUNCTION (this);

  if (m_receivedTransportParameters)
    {
      AbortConnection (
        QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
        "Duplicate transport parameters reception");
      return;
    }
  m_receivedTransportParameters = true;

// TODO: A client MUST NOT include a stateless reset token. A server MUST treat receipt of a stateless_reset_token_transport
//   parameter as a connection error of type TRANSPORT_PARAMETER_ERROR

  uint32_t mask = transportParameters.GetInitialMaxStreamIdBidi ()
    & 0x00000003;
  if ((mask == 0) && m_socketState != CONNECTING_CLT)
    {
      // TODO AbortConnection(QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR, "Invalid Initial Max Stream Id Bidi value provided from Server");
      return;
    }
  else if ((mask == 1) && m_socketState != CONNECTING_SVR)
    {
      // TODO AbortConnection(QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR, "Invalid Initial Max Stream Id Bidi value provided from Client");
      return;
    }

  mask = transportParameters.GetInitialMaxStreamIdUni () & 0x00000003;
  if ((mask == 2) && m_socketState != CONNECTING_CLT)
    {
      // TODO AbortConnection(QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR, "Invalid Initial Max Stream Id Uni value provided from Server");
      return;
    }
  else if ((mask == 3) && m_socketState != CONNECTING_SVR)
    {
      // TODO AbortConnection(QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR, "Invalid Initial Max Stream Id Uni value provided from Client");
      return;
    }

  if (transportParameters.GetMaxPacketSize ()
      < QuicSocketBase::MIN_INITIAL_PACKET_SIZE
      or transportParameters.GetMaxPacketSize () > 65527)
    {
      AbortConnection (
        QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
        "Invalid Max Packet Size value provided");
      return;
    }

// version 15 has removed the upper bound on the idle timeout
// if (transportParameters.GetIdleTimeout () > 600)
//   {
//     AbortConnection (
//         QuicSubheader::TransportErrorCodes_t::TRANSPORT_PARAMETER_ERROR,
//         "Invalid Idle Timeout value provided");
//     return;
//   }

  NS_LOG_DEBUG (
    "Before applying received transport parameters " << " m_initial_max_stream_data " << m_initial_max_stream_data << " m_max_data " << m_max_data << " m_initial_max_stream_id_bidi " << m_initial_max_stream_id_bidi << " m_idleTimeout " << m_idleTimeout << " m_omit_connection_id " << m_omit_connection_id << " m_tcb->m_segmentSize " << m_tcb->m_segmentSize << " m_ack_delay_exponent " << m_ack_delay_exponent << " m_initial_max_stream_id_uni " << m_initial_max_stream_id_uni);

  m_initial_max_stream_data = std::min (
      transportParameters.GetInitialMaxStreamData (),
      m_initial_max_stream_data);
  m_quicl5->UpdateInitialMaxStreamData (m_initial_max_stream_data);

  m_max_data = std::min (transportParameters.GetInitialMaxData (),
                         m_max_data);

  m_initial_max_stream_id_bidi = std::min (
      transportParameters.GetInitialMaxStreamIdBidi (),
      m_initial_max_stream_id_bidi);

  m_idleTimeout = Time (
      std::min (transportParameters.GetIdleTimeout (),
                (uint16_t) m_idleTimeout.Get ().GetSeconds ()) * 1e9);

  m_omit_connection_id = std::min (transportParameters.GetOmitConnection (),
                                   (uint8_t) m_omit_connection_id);

  SetSegSize (
    std::min ((uint32_t) transportParameters.GetMaxPacketSize (),
              m_tcb->m_segmentSize));

//m_stateless_reset_token = std::min(transportParameters.getStatelessResetToken(), m_stateless_reset_token);
  m_ack_delay_exponent = std::min (transportParameters.GetAckDelayExponent (),
                                   m_ack_delay_exponent);

  m_initial_max_stream_id_uni = std::min (
      transportParameters.GetInitialMaxStreamIdUni (),
      m_initial_max_stream_id_uni);

  NS_LOG_DEBUG (
    "After applying received transport parameters " << " m_initial_max_stream_data " << m_initial_max_stream_data << " m_max_data " << m_max_data << " m_initial_max_stream_id_bidi " << m_initial_max_stream_id_bidi << " m_idleTimeout " << m_idleTimeout << " m_omit_connection_id " << m_omit_connection_id << " m_tcb->m_segmentSize " << m_tcb->m_segmentSize << " m_ack_delay_exponent " << m_ack_delay_exponent << " m_initial_max_stream_id_uni " << m_initial_max_stream_id_uni);
}

int
QuicSocketBase::DoConnect (void)
{
  NS_LOG_FUNCTION (this);

  if (m_socketState != IDLE and m_socketState != QuicSocket::LISTENING)
    {
      //m_errno = ERROR_INVAL;
      return -1;
    }

  if (m_socketState == LISTENING)
    {
      SetState (CONNECTING_SVR);
    }
  else if (m_socketState == IDLE)
    {
      SetState (CONNECTING_CLT);
      QuicHeader q;
      SendInitialHandshake (QuicHeader::INITIAL, q, 0);
    }
  return 0;
}

int
QuicSocketBase::DoFastConnect (void)
{
  NS_LOG_FUNCTION (this);
  NS_ABORT_MSG_IF (!IsVersionSupported (m_vers),
                   "0RTT Handshake requested with wrong Initial Version");

  if (m_socketState != IDLE)
    {
      //m_errno = ERROR_INVAL;
      return -1;
    }

  else if (m_socketState == IDLE)
    {
      SetState (OPEN);
      Simulator::ScheduleNow(&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      QuicHeader q;
      SendInitialHandshake (QuicHeader::ZRTT_PROTECTED, q, 0);
    }
  return 0;
}

void
QuicSocketBase::ConnectionSucceeded ()
{ // Wrapper to protected function NotifyConnectionSucceeded() so that it can
  // be called as a scheduled event
  NotifyConnectionSucceeded ();
  // The if-block below was moved from ProcessSynSent() to here because we need
  // to invoke the NotifySend() only after NotifyConnectionSucceeded() to
  // reflect the behaviour in the real world.
  if (GetTxAvailable () > 0)
    {
      NotifySend (GetTxAvailable ());
    }
}

int
QuicSocketBase::DoClose (void)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO (this << " DoClose at time " << Simulator::Now ().GetSeconds ());

  if (m_socketState != IDLE)
    {
      SetState (IDLE);
    }

  SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
  return m_quicl4->RemoveSocket (this);
}

void
QuicSocketBase::ReceivedData (Ptr<Packet> p, const QuicHeader& quicHeader,
                              Address &address)
{
  NS_LOG_FUNCTION (this);

  m_rxTrace (p, quicHeader, this);
  
  //FEC --- [新增] 保存當前處理的 Packet Number 與來源位址 ---
  m_currentProcessingPn = quicHeader.GetPacketNumber();
  m_currentProcessingAddress = address;

  // [項目2-B] 捕捉封包完整位元組（不含 QUIC header），供 ProcessFecTag 使用
  {
    uint32_t pktSize = p->GetSize ();
    m_currentProcessingData.resize (pktSize);
    p->CopyData (m_currentProcessingData.data (), pktSize);
  }

  NS_LOG_INFO ("Received packet of size " << p->GetSize ());

  // check if this packet is not received during the draining period
  if (!m_drainingPeriodEvent.IsRunning ())
    {
      m_idleTimeoutEvent.Cancel ();   // reset the IDLE timeout
      NS_LOG_LOGIC (
        this << " ReceivedData Schedule Close at time " << Simulator::Now ().GetSeconds () << " to expire at time " << (Simulator::Now () + m_idleTimeout.Get ()).GetSeconds ());
      m_idleTimeoutEvent = Simulator::Schedule (m_idleTimeout,
                                                &QuicSocketBase::Close, this);
    }
  else   // If the socket is in Draining Period, discard the packets
    {
      return;
    }

  int onlyAckFrames = 0;
  bool unsupportedVersion = false;

  if (quicHeader.IsORTT () and m_socketState == LISTENING)
    {

      if (m_serverBusy)
        {
          AbortConnection (QuicSubheader::TransportErrorCodes_t::SERVER_BUSY,
                           "Server too busy to accept new connections");
          return;
        }

      m_couldContainTransportParameters = true;

      onlyAckFrames = m_quicl5->DispatchRecv (p, address);
      m_receivedPacketNumbers.push_back (quicHeader.GetPacketNumber ());

      m_connected = true;
      m_keyPhase == QuicHeader::PHASE_ONE ? m_keyPhase =
        QuicHeader::PHASE_ZERO :
        m_keyPhase =
          QuicHeader::PHASE_ONE;
      SetState (OPEN);
      Simulator::ScheduleNow(&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      m_couldContainTransportParameters = false;

    }
  else if (quicHeader.IsInitial () and m_socketState == CONNECTING_SVR)
    {
      NS_LOG_INFO ("Server receives INITIAL");
      if (m_serverBusy)
        {
          AbortConnection (QuicSubheader::TransportErrorCodes_t::SERVER_BUSY,
                           "Server too busy to accept new connections");
          return;
        }

      if (p->GetSize () < QuicSocketBase::MIN_INITIAL_PACKET_SIZE)
        {
          std::stringstream error;
          error << "Initial Packet smaller than "
                << QuicSocketBase::MIN_INITIAL_PACKET_SIZE << " octects";
          AbortConnection (
            QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
            error.str ().c_str ());
          return;
        }

      onlyAckFrames = m_quicl5->DispatchRecv (p, address);
      m_receivedPacketNumbers.push_back (quicHeader.GetPacketNumber ());

      if (IsVersionSupported (quicHeader.GetVersion ()))
        {
          m_couldContainTransportParameters = false;
          SendInitialHandshake (QuicHeader::HANDSHAKE, quicHeader, p);
        }
      else
        {
          NS_LOG_INFO (this << " WRONG VERSION " << quicHeader.GetVersion ());
          unsupportedVersion = true;
          SendInitialHandshake (QuicHeader::VERSION_NEGOTIATION, quicHeader,
                                p);
        }
      return;
    }
  else if (quicHeader.IsHandshake () and m_socketState == CONNECTING_CLT)   // Undefined compiler behaviour if i try to receive transport parameters
    {
      NS_LOG_INFO ("Client receives HANDSHAKE");

      onlyAckFrames = m_quicl5->DispatchRecv (p, address);
      m_receivedPacketNumbers.push_back (quicHeader.GetPacketNumber ());

      SetState (OPEN);
      Simulator::ScheduleNow(&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      m_couldContainTransportParameters = false;

      SendInitialHandshake (QuicHeader::HANDSHAKE, quicHeader, p);
      return;
    }
  else if (quicHeader.IsHandshake () and m_socketState == CONNECTING_SVR)
    {
      NS_LOG_INFO ("Server receives HANDSHAKE");

      onlyAckFrames = m_quicl5->DispatchRecv (p, address);
      m_receivedPacketNumbers.push_back (quicHeader.GetPacketNumber ());

      SetState (OPEN);
      Simulator::ScheduleNow(&QuicSocketBase::ConnectionSucceeded, this);
      m_congestionControl->CongestionStateSet (m_tcb,
                                               TcpSocketState::CA_OPEN);
      SendPendingData (true);
      return;
    }
  else if (quicHeader.IsVersionNegotiation ()
           and m_socketState == CONNECTING_CLT)
    {
      NS_LOG_INFO ("Client receives VERSION_NEGOTIATION");

      uint8_t *buffer = new uint8_t[p->GetSize ()];
      p->CopyData (buffer, p->GetSize ());

      std::vector<uint32_t> receivedVersions;
      for (uint8_t i = 0; i < p->GetSize (); i = i + 4)
        {
          receivedVersions.push_back (
            buffer[i] + (buffer[i + 1] << 8) + (buffer[i + 2] << 16)
            + (buffer[i + 3] << 24));
          //NS_LOG_INFO(" " << (uint64_t) buffer[i] << " " << (uint64_t)buffer[i+1] << " " << (uint64_t)buffer[i+2] << " " << (uint64_t)buffer[i+3] );
        }

      std::vector<uint32_t> supportedVersions;
      supportedVersions.push_back (QUIC_VERSION);
      supportedVersions.push_back (QUIC_VERSION_DRAFT_10);
      supportedVersions.push_back (QUIC_VERSION_NS3_IMPL);

      uint32_t foundVersion = 0;
      for (uint8_t i = 0; i < receivedVersions.size (); i++)
        {
          for (uint8_t j = 0; j < supportedVersions.size (); j++)
            {
//			NS_LOG_INFO("rec " << receivedVersions[i] << " myvers " << m_supportedVersions[j] );
              if (receivedVersions[i] == supportedVersions[j])
                {
                  foundVersion = receivedVersions[i];
                }
            }
        }

      if (foundVersion != 0)
        {
          NS_LOG_INFO ("A matching supported version is found " << foundVersion << " re-send initial");
          m_vers = foundVersion;
          SendInitialHandshake (QuicHeader::INITIAL, quicHeader, p);
        }
      else
        {
          AbortConnection (
            QuicSubheader::TransportErrorCodes_t::VERSION_NEGOTIATION_ERROR,
            "No supported Version found by the Client");
          return;
        }
      return;
    }
  else if (quicHeader.IsShort () and m_socketState == OPEN)
    {
      // TODOACK here?
      // we need to check if the packet contains only an ACK frame
      // in this case we cannot explicitely ACK it!
      // check if delayed ACK is used
      m_receivedPacketNumbers.push_back (quicHeader.GetPacketNumber ());
      onlyAckFrames = m_quicl5->DispatchRecv (p, address);

    }
  else if (m_socketState == CLOSING)
    {

      AbortConnection (m_transportErrorCode,
                       "Received packet in Closing state");

    }
  else
    {

      return;
    }

  // trigger the process for ACK handling if the received packet was not ACK only
  NS_LOG_DEBUG ("onlyAckFrames " << onlyAckFrames << " unsupportedVersion " << unsupportedVersion);
  if (onlyAckFrames == 1 && !unsupportedVersion)
    {
      m_lastReceived = Simulator::Now();
      NS_LOG_DEBUG ("Call MaybeQueueAck");
      MaybeQueueAck ();
    }

}

uint32_t
QuicSocketBase::GetInitialMaxStreamData () const
{
  return m_initial_max_stream_data;
}

uint32_t
QuicSocketBase::GetConnectionMaxData () const
{
  return m_max_data;
}

void
QuicSocketBase::SetConnectionMaxData (uint32_t maxData)
{
  m_max_data = maxData;
}

QuicSocket::QuicStates_t
QuicSocketBase::GetSocketState () const
{
  return m_socketState;
}

void
QuicSocketBase::SetState (TracedValue<QuicStates_t> newstate)
{
  NS_LOG_FUNCTION (this);

  if (m_quicl4->IsServer ())
    {
      NS_LOG_INFO (
        "Server " << QuicStateName[m_socketState] << " -> " << QuicStateName[newstate] << "");
    }
  else
    {
      NS_LOG_INFO (
        "Client " << QuicStateName[m_socketState] << " -> " << QuicStateName[newstate] << "");
    }

  m_socketState = newstate;
}

bool
QuicSocketBase::IsVersionSupported (uint32_t version)
{
  if (version == QUIC_VERSION || version == QUIC_VERSION_DRAFT_10
      || version == QUIC_VERSION_NS3_IMPL)
    {
      return true;
    }
  else
    {
      return false;
    }
}

void
QuicSocketBase::AbortConnection (uint16_t transportErrorCode,
                                 const char* reasonPhrase,
                                 bool applicationClose)
{
  NS_LOG_FUNCTION (this);

  NS_LOG_INFO (
    "Abort connection " << transportErrorCode << " because " << reasonPhrase);

  m_transportErrorCode = transportErrorCode;

  QuicSubheader quicSubheader;
  Ptr<Packet> frame = Create<Packet> ();
  if (!applicationClose)
    {
      quicSubheader = QuicSubheader::CreateConnectionClose (
          m_transportErrorCode, reasonPhrase);
    }
  else
    {
      quicSubheader = QuicSubheader::CreateApplicationClose (
          m_transportErrorCode, reasonPhrase);
    }
  frame->AddHeader (quicSubheader);

  QuicHeader quicHeader;
  switch (m_socketState)
    {
    case CONNECTING_CLT:
      quicHeader = QuicHeader::CreateInitial (m_connectionId, m_vers,
                                              m_tcb->m_nextTxSequence++);
      break;
    case CONNECTING_SVR:
      quicHeader = QuicHeader::CreateHandshake (m_connectionId, m_vers,
                                                m_tcb->m_nextTxSequence++);
      break;
    case OPEN:
      quicHeader =
        !m_connected ?
        QuicHeader::CreateHandshake (m_connectionId, m_vers,
                                     m_tcb->m_nextTxSequence++) :
        QuicHeader::CreateShort (m_connectionId,
                                 m_tcb->m_nextTxSequence++,
                                 !m_omit_connection_id, m_keyPhase);
      break;
    case CLOSING:
      quicHeader = QuicHeader::CreateShort (m_connectionId,
                                            m_tcb->m_nextTxSequence++,
                                            !m_omit_connection_id,
                                            m_keyPhase);
      break;
    default:
      NS_ABORT_MSG (
        "AbortConnection in unfeasible Socket State for the request");
      return;
    }
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddAtEnd (frame);
  uint32_t sz = packet->GetSize ();

  m_quicl4->SendPacket (this, packet, quicHeader);
  m_txTrace (packet, quicHeader, this);
  NotifyDataSent (sz);

  Close ();
}

bool
QuicSocketBase::GetReceivedTransportParametersFlag () const
{
  return m_receivedTransportParameters;
}

bool
QuicSocketBase::CheckIfPacketOverflowMaxDataLimit (
  std::vector<std::pair<Ptr<Packet>, QuicSubheader> > disgregated)
{
  NS_LOG_FUNCTION (this);
  uint32_t validPacketSize = 0;

  for (auto frame_recv_it = disgregated.begin ();
       frame_recv_it != disgregated.end () and !disgregated.empty ();
       ++frame_recv_it)
    {
      QuicSubheader sub = (*frame_recv_it).second;
      // (*frame_recv_it)->PeekHeader (sub);

      if (sub.IsStream () and sub.GetStreamId () != 0)
        {
          validPacketSize += (*frame_recv_it).first->GetSize ();
        }
    }

  if ((m_max_data < m_rxBuffer->Size () + validPacketSize))
    {
      return true;
    }
  return false;
}

uint32_t
QuicSocketBase::GetMaxStreamId () const
{
  return std::max (m_initial_max_stream_id_bidi, m_initial_max_stream_id_uni);
}

uint32_t
QuicSocketBase::GetMaxStreamIdBidirectional () const
{
  return m_initial_max_stream_id_bidi;
}

uint32_t
QuicSocketBase::GetMaxStreamIdUnidirectional () const
{
  return m_initial_max_stream_id_uni;
}

bool
QuicSocketBase::CouldContainTransportParameters () const
{
  return m_couldContainTransportParameters;
}

void
QuicSocketBase::SetCongestionControlAlgorithm (Ptr<TcpCongestionOps> algo)
{
  NS_LOG_FUNCTION (this << algo);
  if (DynamicCast<QuicCongestionOps> (algo) != 0)
    {
      NS_LOG_INFO ("Non-legacy congestion control");
      m_quicCongestionControlLegacy = false;
    }
  else
    {
      NS_LOG_INFO (
        "Legacy congestion control, using only TCP standard functions");
      m_quicCongestionControlLegacy = true;
    }
  m_congestionControl = algo;
}

void
QuicSocketBase::SetSocketSndBufSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  m_socketTxBufferSize = size;
  m_txBuffer->SetMaxBufferSize (size);
}

uint32_t
QuicSocketBase::GetSocketSndBufSize (void) const
{
  return m_txBuffer->GetMaxBufferSize ();
}

void
QuicSocketBase::SetSocketRcvBufSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  m_socketRxBufferSize = size;
  m_rxBuffer->SetMaxBufferSize (size);
}

uint32_t
QuicSocketBase::GetSocketRcvBufSize (void) const
{
  return m_rxBuffer->GetMaxBufferSize ();
}

void
QuicSocketBase::UpdateCwnd (uint32_t oldValue, uint32_t newValue)
{
  m_cWndTrace (oldValue, newValue);
}

void
QuicSocketBase::UpdateSsThresh (uint32_t oldValue, uint32_t newValue)
{
  m_ssThTrace (oldValue, newValue);
}

void
QuicSocketBase::UpdateCongState (TcpSocketState::TcpCongState_t oldValue,
                                 TcpSocketState::TcpCongState_t newValue)
{
  m_congStateTrace (oldValue, newValue);
}

void
QuicSocketBase::UpdateNextTxSequence (SequenceNumber32 oldValue,
                                      SequenceNumber32 newValue)

{
  m_nextTxSequenceTrace (oldValue.GetValue (), newValue.GetValue ());
}

void
QuicSocketBase::UpdateHighTxMark (SequenceNumber32 oldValue, SequenceNumber32 newValue)
{
  m_highTxMarkTrace (oldValue.GetValue (), newValue.GetValue ());
}

void
QuicSocketBase::SetInitialSSThresh (uint32_t threshold)
{
  NS_ABORT_MSG_UNLESS ( (m_socketState == IDLE) || threshold == m_tcb->m_initialSsThresh,
                        "QuicSocketBase::SetSSThresh() cannot change initial ssThresh after connection started.");

  m_tcb->m_initialSsThresh = threshold;
}

uint32_t
QuicSocketBase::GetInitialSSThresh (void) const
{
  return m_tcb->m_initialSsThresh;
}

void
QuicSocketBase::SetInitialPacketSize (uint32_t size)
{
  NS_ABORT_MSG_IF(size < 1200, "The size of the initial packet should be at least 1200 bytes");
  m_initialPacketSize = size;
}

uint32_t
QuicSocketBase::GetInitialPacketSize () const
{
  return m_initialPacketSize;
}

//FEC
// 加在檔案最後面 namespace ns3 結束前

void
QuicSocketBase::SetFecConfiguration (bool enable, uint32_t k, uint32_t p)
{
  NS_LOG_FUNCTION (this << enable << k << p);
  m_enableFec = enable;
  m_fecK = k;
  m_fecP = p;
  // 重置計數器確保從頭開始
  m_currentBlockId = 0; 
  m_currentBlockIdx = 0;
}

void
QuicSocketBase::SendRepairPackets (uint32_t blockId)
{
  NS_LOG_FUNCTION (this << blockId);

  // 直接發送所有 Repair Packets（Burst 模式，不使用 Flow Control 時用）
  for (uint32_t i = 0; i < m_fecP; ++i)
    {
      SendSingleRepairPacket (blockId, i);
    }
  
  NS_LOG_INFO ("Sent " << m_fecP << " Repair Packets for Block " << blockId);
}

void
QuicSocketBase::ScheduleNextRepair (void)
{
  NS_LOG_FUNCTION (this);
  
  if (m_pendingRepairs.empty ())
    {
      return;
    }
  
  // 計算發送間隔 - 設為非常小的值以確保及時發送
  Time interval = MicroSeconds (10);  // 10 微秒
  
  m_repairSendEvent = Simulator::Schedule (interval, &QuicSocketBase::ProcessPendingRepairs, this);
}

void
QuicSocketBase::ProcessPendingRepairs (void)
{
  NS_LOG_FUNCTION (this);
  
  if (m_pendingRepairs.empty ())
    {
      return;
    }
  
  // 批量發送：每次發送多個 Repair Packets（最多 5 個）
  // 這樣可以在保持一定分散的同時，確保 Repair 能及時發出
  uint32_t batchSize = 5;
  uint32_t sent = 0;
  
  while (!m_pendingRepairs.empty () && sent < batchSize)
    {
      FecRepairInfo info = m_pendingRepairs.front ();
      m_pendingRepairs.pop ();
      
      SendSingleRepairPacket (info.blockId, info.repairIndex);
      sent++;
    }
  
  // 如果還有待發送的，繼續排程
  if (!m_pendingRepairs.empty ())
    {
      ScheduleNextRepair ();
    }
}

void
QuicSocketBase::SendSingleRepairPacket (uint32_t blockId, uint32_t repairIndex)
{
  NS_LOG_FUNCTION (this << blockId << repairIndex);

  // [項目2] 從 RS 編碼快取取得 repair symbol 資料
  Ptr<Packet> p;
  auto cacheIt = m_fecRepairCache.find (blockId);
  if (cacheIt != m_fecRepairCache.end () &&
      (repairIndex + 1) * FEC_BLOCK_BYTES <= cacheIt->second.size ())
    {
      const uint8_t* repairPtr = cacheIt->second.data () + repairIndex * FEC_BLOCK_BYTES;
      p = Create<Packet> (repairPtr, FEC_BLOCK_BYTES);
    }
  else
    {
      // 快取不存在時重新編碼（通常不應發生）
      NS_LOG_WARN ("[RS] 快取不存在，重新編碼: block=" << blockId << " repairIdx=" << repairIndex);
      RsEncodeBlock (blockId);
      auto it2 = m_fecRepairCache.find (blockId);
      if (it2 != m_fecRepairCache.end () &&
          (repairIndex + 1) * FEC_BLOCK_BYTES <= it2->second.size ())
        {
          const uint8_t* repairPtr = it2->second.data () + repairIndex * FEC_BLOCK_BYTES;
          p = Create<Packet> (repairPtr, FEC_BLOCK_BYTES);
        }
      else
        {
          p = Create<Packet> (FEC_BLOCK_BYTES);  // zero-filled fallback
        }
    }

  // 附上這個 Block 內 K 個 source symbol 的原始 stream 位置資訊，
  // 讓接收端 FEC 復原後能重建出正確的 STREAM frame 送回應用層，
  // 而不只是在統計上標記「已復原」
  std::vector<uint64_t> metaStreamIds, metaOffsets;
  std::vector<uint32_t> metaLengths;
  auto metaIt = m_fecTxSrcMeta.find (blockId);
  if (metaIt != m_fecTxSrcMeta.end ())
    {
      metaStreamIds.reserve (metaIt->second.size ());
      metaOffsets.reserve (metaIt->second.size ());
      metaLengths.reserve (metaIt->second.size ());
      for (const auto &m : metaIt->second)
        {
          metaStreamIds.push_back (m.streamId);
          metaOffsets.push_back (m.offset);
          metaLengths.push_back (m.length);
        }
    }

  // FEC REPAIR Frame header：宣告 payload 長度 = FEC_BLOCK_BYTES，
  // 讓接收端的 DisgregateRecv 能正確跳過封包 body 裡已經存在的 RS 資料
  // （Serialize() 只會寫入這個長度欄位本身，不會重複填充 payload bytes）
  QuicSubheader repairFrame = QuicSubheader::CreateFecRepair (
      1, FEC_BLOCK_BYTES, metaStreamIds, metaOffsets, metaLengths);
  p->AddHeader (repairFrame);

  // FEC TAG Frame（Sequence = K + repairIndex）
  QuicSubheader fecTag = QuicSubheader::CreateFecTag (
      1, m_fecK + repairIndex, 3, blockId, 0);
  p->AddHeader (fecTag);

  // QUIC Header
  SequenceNumber32 packetNumber = ++m_tcb->m_nextTxSequence;
  QuicHeader head = QuicHeader::CreateShort (
      m_connectionId, packetNumber, !m_omit_connection_id, m_keyPhase);

  NS_LOG_INFO ("[RS] Sending FEC Repair: Block=" << blockId
               << " RepairIdx=" << repairIndex
               << " Seq=" << (m_fecK + repairIndex)
               << " PN=" << packetNumber
               << " Size=" << p->GetSize ());

  m_quicl4->SendPacket (this, p, head);
  g_totalWireBytesSent += (p->GetSize () + 28);
  g_fecRepairCount++;
  m_repairPacketSent++;
  m_txTrace (p, head, this);

  // 這個 Block 的最後一個 Repair 封包送出後，metadata 已無用途，清掉避免累積
  if (repairIndex + 1 >= m_fecP)
    {
      m_fecTxSrcMeta.erase (blockId);
    }
}

void
QuicSocketBase::ProcessFecTag (const QuicSubheader& sub)
{
  uint32_t blockId = sub.GetFecTagId();
  uint32_t idx = sub.GetFecSequence();

  // Repair 封包的 wire 順序固定為 [FEC_TAG][FEC_REPAIR][raw payload]，
  // 所以緊接著這個 FEC_TAG 之後處理的 FEC_REPAIR frame（若存在）一定
  // 屬於同一個 blockId，供 ProcessFecRepair 取用
  m_lastFecRepairBlockId = blockId;

  // Debug: 只在第一個封包時輸出（正常測試保持靜默）
  static bool firstPacket = true;
  if (firstPacket) {
    NS_LOG_INFO ("[FEC ProcessFecTag] First packet: blockId=" << blockId << " idx=" << idx << " m_fecK=" << m_fecK);
    firstPacket = false;
  }
  
  // 建立唯一識別碼用於統計追蹤
  uint64_t packetKey = ((uint64_t)blockId << 32) | idx;
  
  // 確保 m_fecK 有正確的值
  // 在第一次收到 FEC 封包時，從 Config 讀取
  if (m_fecK == 0)
    {
      UintegerValue kVal;
      if (GetAttributeFailSafe("FecK", kVal) && kVal.Get() > 0) {
        m_fecK = kVal.Get();
      } else {
        // Attribute 也沒有設定，使用常見的預設值
        m_fecK = 30;
      }
      
      // 同時設定 m_fecP
      if (m_fecP == 0) {
        UintegerValue pVal;
        if (GetAttributeFailSafe("FecP", pVal) && pVal.Get() > 0) {
          m_fecP = pVal.Get();
        } else {
          m_fecP = 10;
        }
      }
      
      NS_LOG_INFO ("[FEC] Receiver initialized: K=" << m_fecK << " P=" << m_fecP);
    }
  
  uint32_t k = m_fecK;
  
  // === 統計封包接收（獨立於 Block 狀態）===
  // 這個統計必須在任何 return 之前完成
  if (m_countedPackets.find(packetKey) == m_countedPackets.end())
    {
      m_countedPackets.insert(packetKey);
      
      // 判斷是 Source 還是 Repair
      if (idx < k)
        {
          m_sourcePacketReceived++;
        }
      else
        {
          m_repairPacketReceived++;
        }
      
      // 清理過舊的統計追蹤（避免記憶體膨脹）
      // 注意：閾值要足夠大以保留 GoP 統計需要的所有封包記錄
      // 對於長時間模擬，可能需要增加這個值
      if (m_countedPackets.size() > 500000)
        {
          uint64_t threshold = ((uint64_t)(blockId > 5000 ? blockId - 5000 : 0)) << 32;
          auto it = m_countedPackets.begin();
          while (it != m_countedPackets.end() && *it < threshold)
            {
              it = m_countedPackets.erase(it);
            }
        }
    }
  
  // 取得 Block 狀態
  bool isBlockRecovered = (m_recoveredBlocks.find(blockId) != m_recoveredBlocks.end());
  FecRxBlockState &state = m_fecRxBuffer[blockId];
  if (state.k == 0)
    {
      state.k = k;
    }

  // Debug 輸出（正式測試下以 NS_LOG 替代 cout，避免大量輸出）
  NS_LOG_DEBUG ("[FEC RX] Block=" << blockId << " Idx=" << idx
                << " Type=" << ((idx < k) ? "SRC" : "REP")
                << " Done=" << isBlockRecovered
                << " Cnt=" << state.receivedSymbolCount);
  
  // 如果這個封包之前已經被 "人工修復" 過，現在從網路收到了
  if (m_recoveredPacketKeys.find(packetKey) != m_recoveredPacketKeys.end())
    {
       NS_LOG_INFO ("Late Packet Arrived (Reordering): Block=" << blockId << " Idx=" << idx);
       m_latePacketCount++;
       m_recoveredPacketKeys.erase(packetKey);
    }
  
  // 如果這個 Block 已經修復過，不再處理 FEC 邏輯
  if (isBlockRecovered)
    {
      return; 
    }

  // 檢查是否已計數過此 Index（用於 FEC 修復邏輯）
  if (state.receivedIndices.find(idx) == state.receivedIndices.end())
    {
      state.receivedIndices.insert(idx);
      state.receivedSymbolCount++;
      
      // [ACK 修正] 記錄 idx -> 實際 Packet Number 的映射
      // 這樣在 FEC 恢復時，可以用正確的 PN 發送 ACK
      state.indexToPnMap[idx] = m_currentProcessingPn;

      // [Option2/Draft] 儲存此 symbol 的 app payload（不含 QUIC/stream headers）
      {
        // FEC_TAG frame 大小固定為 8 bytes（TagType=1, TagIdLength=3, Redundancy=1byte）
        static const uint32_t FEC_TAG_BYTES = 8;
        std::vector<uint8_t> symBuf (FEC_BLOCK_BYTES, 0);
        uint32_t dataSize = static_cast<uint32_t> (m_currentProcessingData.size ());

        if (idx < state.k)
          {
            // Source symbol：跳過 FEC_TAG，再跳過 stream subheader，取 app payload
            if (dataSize > FEC_TAG_BYTES)
              {
                Ptr<Packet> afterTag = Create<Packet> (
                    m_currentProcessingData.data () + FEC_TAG_BYTES,
                    dataSize - FEC_TAG_BYTES);
                QuicSubheader streamSub;
                afterTag->PeekHeader (streamSub);
                uint32_t streamHdrBytes = streamSub.GetSerializedSize ();
                uint32_t afterHdr = (afterTag->GetSize () > streamHdrBytes)
                                    ? afterTag->GetSize () - streamHdrBytes : 0;
                if (afterHdr > 0)
                  {
                    // 取最多 FEC_BLOCK_BYTES 個位元組（自然截斷末尾的 ACK frame）
                    uint32_t copyLen = std::min (afterHdr, FEC_BLOCK_BYTES);
                    std::memcpy (symBuf.data (),
                                 m_currentProcessingData.data () + FEC_TAG_BYTES + streamHdrBytes,
                                 copyLen);
                  }
              }
          }
        else
          {
            // Repair symbol：RS 資料位於封包末尾 FEC_BLOCK_BYTES 個位元組
            if (dataSize >= FEC_BLOCK_BYTES)
              {
                std::copy (m_currentProcessingData.end () - FEC_BLOCK_BYTES,
                           m_currentProcessingData.end (),
                           symBuf.begin ());
              }
            else
              {
                NS_LOG_WARN ("[RS-RX] Repair packet too small: " << dataSize << " < " << FEC_BLOCK_BYTES);
              }
          }
        state.rxData.push_back (std::move (symBuf));
        state.rxSymIdx.push_back (static_cast<uint8_t> (idx));
      }

      NS_LOG_INFO ("Rx FEC Tag: Block=" << blockId << " Idx=" << idx
                   << " PN=" << m_currentProcessingPn
                   << " Count=" << state.receivedSymbolCount);
      // ★ 新增：寫入正常接收紀錄到 events.csv
     LogFecEv("RECV", m_connectionId, blockId);

      // 注意：是否需要嘗試 FEC Recovery 的判斷，延後到 ProcessFecRepair
      // 才做（見該函式），而不是在這裡立刻呼叫 CheckAndRecover。
      // 原因：Repair 封包的 wire 順序是 [FEC_TAG][FEC_REPAIR][raw payload]，
      // FEC_REPAIR frame 攜帶的 symbol metadata 要等 ProcessFecRepair 執行
      // 完才會寫入 state.symMeta；如果在這裡（FEC_TAG 處理時）就觸發
      // CheckAndRecover，會在 metadata 存入之前就嘗試復原，導致復原出的
      // 資料因為缺少 offset/length 而無法重建成 STREAM frame 送回應用層。
    }
}

void
QuicSocketBase::ProcessFecRepair (const QuicSubheader& sub)
{
  // Repair 封包本身在 wire 上的順序固定為 [FEC_TAG][FEC_REPAIR][raw payload]
  // （見 SendSingleRepairPacket 的 AddHeader 呼叫順序），所以 OnReceivedFrame
  // 一定先處理完同封包的 FEC_TAG（ProcessFecTag，藉此得知 blockId/idx 並計入
  // 統計），才會輪到這裡處理 FEC_REPAIR frame。m_lastFecRepairBlockId 就是
  // ProcessFecTag 剛剛存下的 blockId。
  NS_LOG_INFO ("Rx Repair Payload (Block=" << m_lastFecRepairBlockId << ")");

  // 實際流程中 FEC_TAG 一定先於同封包內的 FEC_REPAIR 被處理（見
  // SendSingleRepairPacket 的 AddHeader 順序：[FEC_TAG][FEC_REPAIR][raw]），
  // 所以這裡讀到的 m_lastFecRepairBlockId 就是這個 Repair 封包所屬的 Block。
  // 把封包攜帶的 K 個 source symbol 位置資訊存起來，供 CheckAndRecover
  // 復原後重建 STREAM frame 使用。
  const std::vector<uint64_t> &streamIds = sub.GetFecSymStreamIds ();
  if (!streamIds.empty ())
    {
      const std::vector<uint64_t> &offsets = sub.GetFecSymOffsets ();
      const std::vector<uint32_t> &lengths = sub.GetFecSymLengths ();
      FecRxBlockState &state = m_fecRxBuffer[m_lastFecRepairBlockId];
      if (state.symMeta.empty ())
        {
          state.symMeta.resize (streamIds.size ());
          for (size_t si = 0; si < streamIds.size (); ++si)
            {
              state.symMeta[si] = FecSymbolMeta{streamIds[si], offsets[si], lengths[si]};
            }
        }
    }

  // metadata（若有）已經存好，現在才是嘗試 FEC Recovery 的時機。
  // 每個 Repair 封包都恰好對應一次這裡的呼叫，CheckAndRecover 內部會自行
  // 判斷是否已經收到 K 個以上 symbol、是否已修復過，不需要在這裡重複判斷。
  CheckAndRecover (m_lastFecRepairBlockId);
}

void
QuicSocketBase::CheckAndRecover (uint32_t blockId)
{
  FecRxBlockState &state = m_fecRxBuffer[blockId];

  // 如果已經恢復過，就不再處理
  if (state.isRecovered) return;

  // 判斷條件：收到的總數 >= K
  if (state.receivedSymbolCount >= state.k)
    {
      // --- 步驟 A: 計算收到的 Source 和 Repair 數量 ---
      uint32_t receivedSourceCount = 0;
      uint32_t receivedRepairCount = 0;
      
      for (auto idx : state.receivedIndices)
        {
          if (idx < state.k)
            receivedSourceCount++;
          else
            receivedRepairCount++;
        }
      
      uint32_t missingSourceCount = state.k - receivedSourceCount;
      
      // --- 步驟 B: 如果所有 Source 都收到了，標記完成 ---
      if (missingSourceCount == 0)
        {
          state.isRecovered = true;
          m_recoveredBlocks.insert(blockId);
          m_fecRxBuffer.erase(blockId);
          NS_LOG_INFO ("Block " << blockId << " complete (No Loss). Sources=" << receivedSourceCount << " Repairs=" << receivedRepairCount); 
          return;
        }
      
      // --- 步驟 C: 檢查是否有足夠的封包進行修復 ---
      // FEC 修復條件：收到的總封包數 >= K
      // 不需要等待所有 Repair 到達，只要有足夠的冗餘即可
      
      uint32_t totalReceived = receivedSourceCount + receivedRepairCount;
      
      // 安全檢查：確保收到的總數 >= K
      if (totalReceived < state.k)
        {
          // 這不應該發生（因為觸發條件是 receivedSymbolCount >= K）
          NS_LOG_WARN ("FEC Error: Block " << blockId << " totalReceived=" << totalReceived << " < K=" << state.k);
          return;
        }
      
      // 檢查是否有足夠的 Repair 來修復丟失的 Source
      // 需要的 Repair 數量 = 丟失的 Source 數量
      if (receivedRepairCount < missingSourceCount)
        {
          // Repair 不夠，無法修復，繼續等待
          NS_LOG_INFO ("FEC Waiting: Block " << blockId 
                       << " MissingSrc=" << missingSourceCount 
                       << " ReceivedRepair=" << receivedRepairCount
                       << " (Need " << missingSourceCount << " repairs to recover)");
          return;
        }
      
      // --- 步驟 D: FEC 解碼（透過 FecCodec 介面，可切換演算法）---
      NS_ABORT_MSG_IF (!m_fecCodec, "[FEC] m_fecCodec 未初始化");

      // 組建 K 個 block：先填已收 source，再補 repair 至滿 K 個
      std::vector<std::vector<uint8_t>> decodeBufs;
      std::vector<uint8_t> decodeIdx;
      decodeBufs.reserve (state.k);
      decodeIdx.reserve (state.k);

      for (size_t si = 0; si < state.rxSymIdx.size (); si++)
        if (state.rxSymIdx[si] < state.k)
          {
            decodeBufs.push_back (state.rxData[si]);
            decodeIdx.push_back (state.rxSymIdx[si]);
          }
      for (size_t si = 0; si < state.rxSymIdx.size () && decodeBufs.size () < state.k; si++)
        if (state.rxSymIdx[si] >= state.k)
          {
            decodeBufs.push_back (state.rxData[si]);
            decodeIdx.push_back (state.rxSymIdx[si]);
          }

      bool success = false;
      if (decodeBufs.size () == state.k)
        {
          success = m_fecCodec->Decode (state.k, m_fecP, FEC_BLOCK_BYTES,
                                        decodeBufs, decodeIdx);
          if (!success)
            NS_LOG_WARN ("[FEC-RX] Decode 失敗: block=" << blockId
                         << " codec=" << m_fecCodec->Name ());
        }
      else
        {
          NS_LOG_WARN ("[FEC-RX] 無法組成 K=" << state.k
                       << " blocks (got " << decodeBufs.size () << ")");
        }
// ... 前面是 m_fecCodec->Decode ...

      if (success)
        {
          // ★ 1. 加在這裡：記錄解碼修復成功
          LogFecEv("FEC_RECOVER", m_connectionId, blockId);

          NS_LOG_INFO ("FEC RECOVERY SUCCESS: Block " << blockId 
                       << " (Missing=" << missingSourceCount 
                       << " RecvSrc=" << receivedSourceCount 
                       << " RecvRepair=" << receivedRepairCount << ")");
                
          state.isRecovered = true;
          
          // ... 下面保持原樣 ...

          // decode 成功後，decodeBufs/decodeIdx 中原本存 Repair symbol 的位置
          // 已被原地覆寫為還原出的 source symbol 資料，索引也更新為對應的
          // source index。建立 index -> 位置 的對照表，供下面重建 STREAM
          // frame 時取出正確的還原資料。
          std::map<uint8_t, size_t> idxToPos;
          for (size_t di = 0; di < decodeIdx.size (); ++di)
            {
              idxToPos[decodeIdx[di]] = di;
            }

          // [ACK 修正] 計算遺失封包的 PN
          // 策略：使用同 Block 內已收到封包的 PN 來估算
          // 假設同一個 Block 的封包 PN 是連續的
          // 找到已收到的最小和最大 Source PN，然後推算遺失封包的 PN
          
          SequenceNumber32 minPn(UINT32_MAX), maxPn(0);
          uint32_t minIdx = UINT32_MAX, maxIdx = 0;
          
          for (const auto& pair : state.indexToPnMap)
            {
              uint32_t pairIdx = pair.first;
              SequenceNumber32 pn = pair.second;
              
              // 只考慮 Source 封包（idx < k）來建立 PN 估算基準
              if (pairIdx < state.k)
                {
                  if (pn < minPn) { minPn = pn; minIdx = pairIdx; }
                  if (pn > maxPn) { maxPn = pn; maxIdx = pairIdx; }
                }
            }
          
          // 計算 PN 的步進值（正常情況下應該是 1）
          int32_t pnStep = 1;
          if (maxIdx > minIdx && maxIdx != UINT32_MAX)
            {
              pnStep = (maxPn.GetValue() - minPn.GetValue()) / (maxIdx - minIdx);
              if (pnStep <= 0) pnStep = 1;
            }

          // [項目3] 收集恢復的 PN，用於 FEC_ACK
          std::vector<uint64_t> fecAckPnList;
          SequenceNumber32 latestRecoveredPn(0);

          // 只對真正丟失的封包計數
          for (uint32_t i = 0; i < state.k; ++i)
            {
              if (state.receivedIndices.find(i) == state.receivedIndices.end())
                {
                  m_fecRecoveredCount++;

                  uint64_t packetKey = ((uint64_t)blockId << 32) | i;
                  m_recoveredPacketKeys.insert(packetKey);

                  if (m_countedPackets.find(packetKey) == m_countedPackets.end())
                    {
                      m_countedPackets.insert(packetKey);
                    }

                  // [ACK 修正] 估算遺失封包的 PN
                  SequenceNumber32 recoveredPn;
                  if (minIdx != UINT32_MAX)
                    {
                      // 基於已知的 PN 推算：minPn + (i - minIdx) * step
                      int32_t offset = (int32_t)i - (int32_t)minIdx;
                      recoveredPn = SequenceNumber32(minPn.GetValue() + offset * pnStep);
                    }
                  else
                    {
                      // Fallback: 使用 Block 內的相對位置（舊方法）
                      recoveredPn = SequenceNumber32(blockId * state.k + i);
                    }

                  NS_LOG_INFO ("Recovered Missing Packet: Block=" << blockId
                               << " Idx=" << i << " EstimatedPN=" << recoveredPn);

                  // === 真正把復原出的資料送回應用層（而非只做統計）===
                  // 用 Repair 封包攜帶來的 metadata（streamId/offset/length）
                  // 把解碼還原出的 bytes 重新包成一個 STREAM frame，交給對應
                  // 的 stream 走正常的 in-order/reassembly 路徑（見
                  // QuicStreamBase::Recv）。這樣即使原始封包真的遺失，
                  // 應用層還是能拿到正確資料，而不會卡在等待這個 offset
                  // 導致後續資料一直堆在 rx buffer 裡直到滿了觸發 abort。
                  auto posIt = idxToPos.find (static_cast<uint8_t> (i));
                  if (posIt != idxToPos.end () && i < state.symMeta.size ())
                    {
                      const std::vector<uint8_t> &recovered = decodeBufs[posIt->second];
                      const FecSymbolMeta &meta = state.symMeta[i];
                      uint32_t copyLen = std::min (static_cast<uint32_t> (recovered.size ()),
                                                    meta.length);
                      if (copyLen > 0)
                        {
                          Ptr<Packet> recoveredPkt = Create<Packet> (recovered.data (), copyLen);
                          QuicSubheader streamSub = QuicSubheader::CreateStreamSubHeader (
                              meta.streamId, meta.offset, copyLen, true, true, false);

                          Ptr<QuicStreamBase> rxStream = m_quicl5->SearchStream (meta.streamId);
                          if (rxStream == nullptr)
                            {
                              m_quicl5->CreateStream (QuicStream::RECEIVER, meta.streamId);
                              rxStream = m_quicl5->SearchStream (meta.streamId);
                            }
                          if (rxStream != nullptr)
                            {
                              NS_LOG_INFO ("[FEC-RX] Re-injecting recovered app data: Block="
                                           << blockId << " Idx=" << i
                                           << " StreamId=" << meta.streamId
                                           << " Offset=" << meta.offset << " Len=" << copyLen);
                              rxStream->Recv (recoveredPkt, streamSub, m_currentProcessingAddress);
                            }
                          else
                            {
                              NS_LOG_WARN ("[FEC-RX] 找不到/無法建立 Stream " << meta.streamId
                                           << "，無法重新注入復原資料");
                            }
                        }
                    }
                  else
                    {
                      NS_LOG_WARN ("[FEC-RX] Block=" << blockId << " Idx=" << i
                                   << " 缺少 symbol metadata，無法重建 STREAM frame"
                                   << "（可能所有 Repair 封包都未攜帶到 metadata）");
                    }

                  m_receivedPacketNumbers.push_back(recoveredPn);

                  // [項目3] 收集到 FEC_ACK 列表
                  fecAckPnList.push_back(recoveredPn.GetValue());
                  if (recoveredPn > latestRecoveredPn)
                    latestRecoveredPn = recoveredPn;
                }
            }
          m_recoveredBlocks.insert(blockId);
          m_fecRxBuffer.erase(blockId);

          // 清理過舊的歷史紀錄
          if (blockId > m_lastRecoveredBlockId) m_lastRecoveredBlockId = blockId;
          if (m_recoveredBlocks.size() > 500)
            {
              auto it = m_recoveredBlocks.begin();
              while (it != m_recoveredBlocks.end() && *it < m_lastRecoveredBlockId - 200)
                {
                  it = m_recoveredBlocks.erase(it);
                }
            }

          // [項目3] 建立 FEC_ACK Frame 並排入等待發送
          if (!fecAckPnList.empty () && m_connected && m_socketState == OPEN)
            {
              uint64_t restoredBytes = fecAckPnList.size() * 512; // 估算 payload 大小
              m_pendingFecAckFrame = QuicSubheader::CreateFecAck (
                  latestRecoveredPn.GetValue (),
                  restoredBytes,
                  (uint64_t)fecAckPnList.size (),
                  fecAckPnList);
              m_hasPendingFecAck = true;
              NS_LOG_INFO ("FEC_ACK queued: Block=" << blockId
                           << " RestoredPkts=" << fecAckPnList.size ());
            }
// ... 上面是一大串處理 PN 和 ACK 的邏輯 ...
          
          MaybeQueueAck();
        }
      else
        {
          // ★ 2. 加在這裡：確定修復失敗
          LogFecEv("FEC_FAIL", m_connectionId, blockId);

          NS_LOG_INFO ("FEC RECOVERY FAILED: Block " << blockId 
                       << " (Received=" << state.receivedSymbolCount 
                       << " K=" << state.k << ")");
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// [項目2] 真實 RS 編碼
// ─────────────────────────────────────────────────────────────────

// 確定性填充：(blockId, symIdx) → 固定偽隨機位元組序列
static void FecFillSourcePattern (uint32_t blockId, uint32_t symIdx, uint8_t* buf, uint32_t blockBytes)
{
  uint32_t v = blockId * 65537u + symIdx * 2654435761u;
  for (uint32_t i = 0; i < blockBytes; i++)
    {
      v = v * 1664525u + 1013904223u;
      buf[i] = static_cast<uint8_t>(v >> 24);
    }
}

void
QuicSocketBase::SetFecCodec (std::unique_ptr<FecCodec> codec)
{
  NS_LOG_INFO ("[FEC] 切換編解碼器: " << codec->Name ());
  m_fecCodec = std::move (codec);
}

void
QuicSocketBase::SetFecCodecType (std::string type)
{
  m_fecCodecType = type;
  if (type == "vdm")
    m_fecCodec = std::make_unique<VandermondeRsCodec> ();
  else
    m_fecCodec = std::make_unique<Cm256Codec> ();
  NS_LOG_INFO ("[FEC] FecCodecType=" << type << " → " << m_fecCodec->Name ());
}

std::string
QuicSocketBase::GetFecCodecType () const
{
  return m_fecCodecType;
}

void
QuicSocketBase::RsEncodeBlock (uint32_t blockId)
{
  NS_ABORT_MSG_IF (!m_fecCodec, "[FEC] m_fecCodec 未初始化");

  // [項目2-B] 使用真實 source symbol 資料；若快取不完整則退回偽隨機
  std::vector<std::vector<uint8_t>> srcBufs;
  auto txIt = m_fecTxSrcData.find (blockId);
  if (txIt != m_fecTxSrcData.end () && txIt->second.size () == m_fecK)
    {
      srcBufs = txIt->second;
    }
  else
    {
      NS_LOG_WARN ("[FEC] Block " << blockId << " source data 不完整 (got "
                   << (txIt != m_fecTxSrcData.end () ? txIt->second.size () : 0)
                   << "/" << m_fecK << ")，使用偽隨機備援");
      srcBufs.assign (m_fecK, std::vector<uint8_t>(FEC_BLOCK_BYTES, 0));
      for (uint32_t i = 0; i < m_fecK; i++)
        FecFillSourcePattern (blockId, i, srcBufs[i].data (), FEC_BLOCK_BYTES);
    }

  std::vector<std::vector<uint8_t>> repairSymbols;
  if (!m_fecCodec->Encode (m_fecK, m_fecP, FEC_BLOCK_BYTES, srcBufs, repairSymbols))
    {
      NS_LOG_WARN ("[FEC] Encode 失敗: block=" << blockId
                   << " codec=" << m_fecCodec->Name ());
      return;
    }

  // 將 P 個 repair symbol 連續存入 repairBuf（維持原有快取格式）
  std::vector<uint8_t> repairBuf (m_fecP * FEC_BLOCK_BYTES, 0);
  for (uint32_t i = 0; i < m_fecP && i < repairSymbols.size (); i++)
    std::copy (repairSymbols[i].begin (), repairSymbols[i].end (),
               repairBuf.begin () + i * FEC_BLOCK_BYTES);

  m_fecRepairCache[blockId] = std::move (repairBuf);
  m_fecTxSrcData.erase (blockId);

  NS_LOG_INFO ("[FEC] Block " << blockId << " 編碼完成 codec=" << m_fecCodec->Name ()
               << " K=" << m_fecK << " P=" << m_fecP << " BlockBytes=" << FEC_BLOCK_BYTES);

  while (m_fecRepairCache.size () > 32)
    m_fecRepairCache.erase (m_fecRepairCache.begin ());
}

uint32_t
QuicSocketBase::GetFecRecoveredCount () const
{
  return m_fecRecoveredCount;
}

uint64_t
QuicSocketBase::GetStreamBytesReceived () const
{
  return m_streamBytesReceived;
}

uint32_t
QuicSocketBase::GetFecAckSentCount () const
{
  return m_fecAckSentCount;
}

uint32_t
QuicSocketBase::GetFecAckReceivedCount () const
{
  return m_fecAckReceivedCount;
}

uint32_t 
QuicSocketBase::GetSourcePacketSent () const
{
  return m_sourcePacketSent;
}

uint32_t 
QuicSocketBase::GetSourcePacketReceived () const
{
  return m_sourcePacketReceived;
}

uint32_t 
QuicSocketBase::GetSourcePacketLost () const
{
  // 計算真正丟失的 Source Packet = 發送 - 接收 (含修復)
  // 注意：m_sourcePacketReceived 已經包含直接收到的 + FEC 修復的
  if (m_sourcePacketSent > m_sourcePacketReceived)
    {
      return m_sourcePacketSent - m_sourcePacketReceived;
    }
  return 0;
}

uint32_t 
QuicSocketBase::GetRepairPacketSent () const
{
  return m_repairPacketSent;
}

uint32_t 
QuicSocketBase::GetRepairPacketReceived () const
{
  return m_repairPacketReceived;
}

uint32_t 
QuicSocketBase::GetLatePacketCount () const
{
  return m_latePacketCount;
}

std::vector<uint32_t>
QuicSocketBase::GetDeliveredSourceIndices () const
{
  // 回傳所有成功送達的 Source 封包索引
  // m_countedPackets 的格式是 (blockId << 32) | idx
  // 我們只需要 Source 封包（idx < K）
  std::vector<uint32_t> result;
  
  // 使用 m_fecK，如果沒設定則從設定檔讀取
  uint32_t k = m_fecK;
  if (k == 0) {
    // 嘗試從全域設定讀取
    UintegerValue kVal;
    if (GetAttributeFailSafe("FecK", kVal)) {
      k = kVal.Get();
    }
    if (k == 0) {
      k = 30;  // 最後的 fallback
      NS_LOG_WARN("GetDeliveredSourceIndices: m_fecK=0, using default K=" << k);
    }
  }
  
  if (!m_countedPackets.empty()) {
    uint64_t minKey = *m_countedPackets.begin();
    uint64_t maxKey = *m_countedPackets.rbegin();
    uint32_t minBlockId = (uint32_t)(minKey >> 32);
    uint32_t minIdx2 = (uint32_t)(minKey & 0xFFFFFFFF);
    uint32_t maxBlockId = (uint32_t)(maxKey >> 32);
    uint32_t maxIdx2 = (uint32_t)(maxKey & 0xFFFFFFFF);
    NS_LOG_INFO ("[GetDeliveredSourceIndices] m_countedPackets.size()=" << m_countedPackets.size()
                 << " K=" << k
                 << " minKey=(Block=" << minBlockId << ",Idx=" << minIdx2 << ")"
                 << " maxKey=(Block=" << maxBlockId << ",Idx=" << maxIdx2 << ")");
  }
  
  for (const auto& packetKey : m_countedPackets) {
    uint32_t blockId = (uint32_t)(packetKey >> 32);
    uint32_t idx = (uint32_t)(packetKey & 0xFFFFFFFF);
    
    // 只取 Source 封包（idx < K）
    if (idx < k) {
      // 計算全域封包索引 = blockId * K + idx
      uint32_t globalIdx = blockId * k + idx;
      result.push_back(globalIdx);
    }
  }
  
  return result;
}

} // namespace ns3
