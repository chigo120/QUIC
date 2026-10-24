#include "fec-recovery-model.h"
#include "ns3/log.h"
#include "ns3/random-variable-stream.h"
#include "ns3/double.h"
#include <cmath>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("FecRecoveryModel");

bool 
FecRecoveryModel::IsRecovered (uint32_t n, uint32_t k, FecScheme scheme)
{
    if (n < k) {
        return false;
    }

    double failureProb = 1.0;
    double overhead = (double)(n - k); 

    if (scheme == RAPTOR_Q) {
        failureProb = 0.01 * std::pow(0.01, overhead);
    } else if (scheme == RAPTOR_CODES) {
        failureProb = 0.85 * std::pow(0.567, overhead);
    } else if (scheme == REED_SOLOMON) {
        failureProb = 0.0;
    }

    if (failureProb > 1.0) failureProb = 1.0;
    if (failureProb < 0.0) failureProb = 0.0;

    Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable> ();
    double roll = uv->GetValue(0.0, 1.0);

    bool success = (roll >= failureProb);
    
    NS_LOG_INFO("FEC Check: Scheme=" << scheme << " N=" << n << " K=" << k 
                << " Overhead=" << overhead
                << " Pf=" << failureProb << " Roll=" << roll 
                << " Result=" << (success ? "Success" : "Fail"));

    return success;
}

} // namespace ns3
