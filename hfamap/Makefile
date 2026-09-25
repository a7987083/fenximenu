ARCHS = arm64
TARGET = iphone:clang:latest:12.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HFAMapUniversal

V2519_LOADED_GENERATED := $(shell python3 tools/generate_v2519_loaded_safe.py)
V2519_SENDER_GENERATED := $(shell python3 tools/generate_v2519_sender_safe.py)

HFAMapUniversal_FILES = src/HFAMapEntry.mm src/HFAMapVersion259.mm src/HFAMapVersion2510.mm src/HFAMapVersion2511.mm src/HFAMapVersion2512.mm src/HFAMapVersion2513.mm src/HFAMapVersion2514.mm src/HFAMapVersion2515.mm src/HFAMapVersion2516.mm src/HFAMapVersion2517.mm src/HFAMapVersion2518.mm src/HFAMapVersion2519.mm src/HFAMapBundleRootScanner.mm src/HFAMapCore.mm src/HFAMapDiagnostics.mm src/HFAMapFastDiscovery.mm src/HFAMapImageProbe.mm src/HFAMapMenuBinaryAnalyzer.mm src/HFAMapStrippedActionAnalyzer.mm src/HFAMapHandlerBranchProvenanceResolver.mm src/HFAMapFeatureBranchProvenance.mm src/HFAMapSenderDerivedProvenanceResolver2519.mm src/HFAMapFeatureContextAnalyzer.mm src/HFAMapFeatureHandlerResolver.mm src/HFAMapStaticCatalog.mm src/HFAMapStaticCatalogBridge.mm src/HFAMapDescriptorStaticCallbackResolver.mm src/HFAMapImportedDylibEvidenceAnalyzer.mm src/HFAMapLoadedDylibEvidenceResolver2519.mm src/HFAMapRuntimeRootGraphResolver.mm src/HFAMapDirectedDescriptorResolver.mm src/HFAMapSecretWrapperEvidenceResolver.mm src/HFAMapLoadedMenuFeatureEnumerator.mm src/HFAMapFeatureOwnershipCorrelator.mm src/HFAMapObjCActionInventory.mm src/HFAIL2CPPMethodIndex.mm src/HFAIL2CPPMethodRangeIndex.mm src/HFAMapResolver.mm src/HFAMapHookSemantic.mm src/HFAMapRuntimeProbe.mm src/HFAIL2CPPRuntimeProbeSafe.mm src/HFAMapOutputName.mm src/HFAMapPatchV1.mm
HFAMapUniversal_CFLAGS = -O2 -fno-stack-protector -Wno-deprecated-declarations -I$(THEOS_PROJECT_DIR)/compat
HFAMapUniversal_FRAMEWORKS = UIKit Foundation QuartzCore

include $(THEOS_MAKE_PATH)/tweak.mk
