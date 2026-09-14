ARCHS = arm64
TARGET = iphone:clang:latest:12.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HFAMapUniversal

HFAMapUniversal_FILES = src/HFAMapLegacy.m src/HFAMapPatchExecutionTrace.m src/HFAMapSecretCallGraphProbe.m src/HFAMapGenericMenuResolver.m src/HFAMapJailpatchRuntimeProfiler.m src/HFAMapJailpatchSelectorResolver.m src/HFAMapFeatureV2UI.m src/HFAPatchConsumerEmbed.m
HFAMapUniversal_CFLAGS = -Oz -fno-stack-protector -fno-builtin -Wno-empty-body -Wno-deprecated-declarations
HFAMapUniversal_LDFLAGS += $(THEOS_PROJECT_DIR)/vendor/libdobby.a -lc++
HFAMapUniversal_FRAMEWORKS = UIKit Foundation

include $(THEOS_MAKE_PATH)/tweak.mk
