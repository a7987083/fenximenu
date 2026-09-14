from pathlib import Path

consumer = Path('hfapatch-consumer/src/HFAPatchConsumer.m')
embed = Path('hfamap/src/HFAPatchConsumerEmbed.m')
ui = Path('hfamap/src/HFAMapFeatureV2UI.m')

c = consumer.read_text()
e = embed.read_text()
u = ui.read_text()

old = '''static dispatch_source_t gHFAPCTimer;\n\n__attribute__((constructor)) static void HFAPCInit(void) {\n    HFAPCLog(@"[LOAD] HFAPatchConsumerPlayback v%@ pid=%d", HFAPCVersion, getpid());\n    dispatch_queue_t queue = dispatch_queue_create("com.hfa.patchconsumer.playback", DISPATCH_QUEUE_SERIAL);\n    gHFAPCTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);\n    dispatch_source_set_timer(gHFAPCTimer,\n                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),\n                              (uint64_t)(1 * NSEC_PER_SEC),\n                              (uint64_t)(100 * NSEC_PER_MSEC));\n    dispatch_source_set_event_handler(gHFAPCTimer, ^{\n        HFAPCProcessCommand();\n    });\n    dispatch_resume(gHFAPCTimer);\n}\n'''
new = '''static dispatch_source_t gHFAPCTimer;\nstatic dispatch_once_t gHFAPCStartOnce;\n\nvoid HFAPCStartPlaybackEngine(void) {\n    dispatch_once(&gHFAPCStartOnce, ^{\n        HFAPCLog(@"[LOAD] HFAPatchConsumerPlayback v%@ pid=%d mode=lazy", HFAPCVersion, getpid());\n        dispatch_queue_t queue = dispatch_queue_create("com.hfa.patchconsumer.playback", DISPATCH_QUEUE_SERIAL);\n        gHFAPCTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);\n        dispatch_source_set_timer(gHFAPCTimer,\n                                  dispatch_time(DISPATCH_TIME_NOW, (int64_t)(250 * NSEC_PER_MSEC)),\n                                  (uint64_t)(1 * NSEC_PER_SEC),\n                                  (uint64_t)(100 * NSEC_PER_MSEC));\n        dispatch_source_set_event_handler(gHFAPCTimer, ^{\n            HFAPCProcessCommand();\n        });\n        dispatch_resume(gHFAPCTimer);\n    });\n}\n\n#ifndef HFA_PATCH_CONSUMER_EMBEDDED\n__attribute__((constructor)) static void HFAPCInit(void) {\n    HFAPCStartPlaybackEngine();\n}\n#endif\n'''
if c.count(old) != 1:
    raise SystemExit(f'consumer constructor anchor mismatch: {c.count(old)}')
c = c.replace(old, new, 1)

embed_anchor = '#include "../../hfapatch-consumer/src/HFAPatchVMCompat.h"\n#include "../../hfapatch-consumer/src/HFAPatchConsumer.m"'
embed_repl = '#define HFA_PATCH_CONSUMER_EMBEDDED 1\n#include "../../hfapatch-consumer/src/HFAPatchVMCompat.h"\n#include "../../hfapatch-consumer/src/HFAPatchConsumer.m"'
if e.count(embed_anchor) != 1:
    raise SystemExit(f'embed anchor mismatch: {e.count(embed_anchor)}')
e = e.replace(embed_anchor, embed_repl, 1)

import_anchor = '#import <UIKit/UIKit.h>\n'
if u.count(import_anchor) != 1:
    raise SystemExit(f'ui import anchor mismatch: {u.count(import_anchor)}')
u = u.replace(import_anchor, import_anchor + '\nextern void HFAPCStartPlaybackEngine(void);\n', 1)

write_anchor = '''    if (![command isKindOfClass:[NSDictionary class]] || ![NSJSONSerialization isValidJSONObject:command]) {\n        if (reasonOut) *reasonOut = @"invalid-command";\n        return NO;\n    }\n    NSString *path = [HFAV2Documents() stringByAppendingPathComponent:@"HFAPatchPlayback.command.json"];'''
write_repl = '''    if (![command isKindOfClass:[NSDictionary class]] || ![NSJSONSerialization isValidJSONObject:command]) {\n        if (reasonOut) *reasonOut = @"invalid-command";\n        return NO;\n    }\n    // Embedded playback is deliberately lazy-started. Merely injecting HFAMap or\n    // rendering/reloading JSON must not start the runtime executor.\n    HFAPCStartPlaybackEngine();\n    NSString *path = [HFAV2Documents() stringByAppendingPathComponent:@"HFAPatchPlayback.command.json"];'''
if u.count(write_anchor) != 1:
    raise SystemExit(f'ui write anchor mismatch: {u.count(write_anchor)}')
u = u.replace(write_anchor, write_repl, 1)

consumer.write_text(c)
embed.write_text(e)
ui.write_text(u)
print('patched HFAMap v1.9.37.1 SafeStart: embedded consumer is lazy-start only')
