ARCHS = arm64
TARGET = iphone:clang:latest:12.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HFAMapUniversal

HFAMapUniversal_FILES = src/HFAMapEntry.mm src/HFAMapCore.mm src/HFAMapDiagnostics.mm src/HFAMapImageProbe.mm src/HFAMapResolver.mm src/HFAMapOutputName.mm
HFAMapUniversal_CFLAGS = -O2 -fno-stack-protector -Wno-deprecated-declarations
HFAMapUniversal_FRAMEWORKS = UIKit Foundation QuartzCore

include $(THEOS_MAKE_PATH)/tweak.mk
