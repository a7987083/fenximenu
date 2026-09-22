#pragma once

#ifdef __OBJC__
#import <Foundation/Foundation.h>

// Builds a read-only, bounded Assembly-CSharp method-pointer index using
// dynamically resolved IL2CPP exports. No method is invoked and no game memory
// is written. The result is analysis-only evidence.
NSDictionary *HFAIL2CPPBuildMethodIndex(NSTimeInterval deadline);

// Exact method-entry lookup. Returns a record only when address == methodPointer.
NSDictionary *HFAIL2CPPMethodForRuntimeAddress(const void *address);

// H5GG 1.9.6-inspired instruction-offset lookup implemented as a fail-closed
// native range index: [methodStart, nextMethodStart), same Unity executable
// segment, bounded maximum span. Exact entries are returned as exact matches.
NSDictionary *HFAIL2CPPMethodContainingRuntimeAddress(const void *address);
#endif
