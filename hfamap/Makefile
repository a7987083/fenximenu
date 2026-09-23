ARCHS = arm64
TARGET = iphone:clang:latest:12.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HFAMapUniversal

HFAMapUniversal_FILES = src/HFAMapEntry.mm src/HFAMapCore.mm src/HFAMapDiagnostics.mm src/HFAMapFastDiscovery.mm src/HFAMapImageProbe.mm src/HFAMapMenuBinaryAnalyzer.mm src/HFAMapStrippedActionAnalyzer.mm src/HFAMapFeatureContextAnalyzer.mm src/HFAMapFeatureHandlerResolver.mm src/HFAMapStaticCatalog.mm src/HFAMapObjCActionInventory.mm src/HFAIL2CPPMethodIndex.mm src/HFAIL2CPPMethodRangeIndex.mm src/HFAMapResolver.mm src/HFAMapHookSemantic.mm src/HFAMapRuntimeProbe.mm src/HFAIL2CPPRuntimeProbe.mm src/HFAMapOutputName.mm src/HFAMapPatchV1.mm
HFAMapUniversal_CFLAGS = -O2 -fno-stack-protector -Wno-deprecated-declarations
HFAMapUniversal_FRAMEWORKS = UIKit Foundation QuartzCore

include $(THEOS_MAKE_PATH)/tweak.mk
