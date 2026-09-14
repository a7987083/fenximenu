ARCHS = arm64
TARGET = iphone:clang:latest:12.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HFAPatchConsumerPlayback

HFAPatchConsumerPlayback_FILES = src/HFAPatchConsumer.m
HFAPatchConsumerPlayback_CFLAGS = -Oz -fno-stack-protector -Wno-deprecated-declarations
HFAPatchConsumerPlayback_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tweak.mk
