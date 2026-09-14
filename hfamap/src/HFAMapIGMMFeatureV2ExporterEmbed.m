// Keep iPhoneOS VM compatibility local to the iGMM Feature-v2 exporter.
// Do not force these SDK headers into HFAMapLegacy.m: that source intentionally
// uses a tiny hand-declared ABI surface to remain independent of UIKit headers.
#include "../../hfapatch-consumer/src/HFAPatchVMCompat.h"
#include <stdlib.h>
#include "HFAMapIGMMFeatureV2Exporter.m"
