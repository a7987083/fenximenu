#pragma once
#import <Foundation/Foundation.h>

// Generic, read-only recovery of plaintext templates produced by runtime
// decrypt wrappers in the selected loaded menu image. The resolver discovers
// wrapper/core relationships structurally and reads naturally initialized
// output buffers; it never invokes unknown menu code and never writes memory.
NSDictionary *HFAMapResolveGenericRuntimeTemplates(NSDictionary *candidate,
                                                   NSTimeInterval deadline);
