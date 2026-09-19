ARCHS = arm64
TARGET = iphone:clang:latest:12.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ZPatchIG

ZPatchIG_FILES = src/HFAMapEntry.mm src/HFAMapCore.mm src/HFAMapDiagnostics.mm src/ZPAppIdentity.mm src/ZPImageProbe.mm src/ZPResolver.mm src/ZPDescriptorObserver.mm src/ZPFeatureResolver.mm src/ZPContainerResolver.mm src/ZPEvidenceGraph.mm src/ZPLegacyOffsetResolver.mm
ZPatchIG_CFLAGS = -O2 -fno-stack-protector -Wno-deprecated-declarations -Wno-unused-function
ZPatchIG_FRAMEWORKS = UIKit Foundation QuartzCore

include $(THEOS_MAKE_PATH)/tweak.mk
