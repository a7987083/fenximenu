ARCHS = arm64
TARGET = iphone:clang:latest:12.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HFAMapUniversal

HFAMapUniversal_FILES = src/HFACanonicalMutation.m src/HFAMapLegacy.m src/HFAMapPatchExecutionTrace.m src/HFAMapSecretCallGraphProbe.m src/HFAMapGenericMenuResolver.m src/HFAMapJailpatchRuntimeProfiler.m src/HFAMapJailpatchSelectorResolver.m src/HFAMapJSONExport.m src/HFAMapAppLocalResolver.m src/HFAMapCyberUI.m
HFAMapUniversal_CFLAGS = -Oz -fno-stack-protector -fno-builtin -Wno-empty-body
HFAMapUniversal_FRAMEWORKS = UIKit Foundation QuartzCore

include $(THEOS_MAKE_PATH)/tweak.mk
