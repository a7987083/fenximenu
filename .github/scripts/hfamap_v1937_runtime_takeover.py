from pathlib import Path

p = Path('hfapatch-consumer/src/HFAPatchConsumer.m')
s = p.read_text()


def once(old, new, label):
    global s
    count = s.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, got {count}')
    s = s.replace(old, new, 1)

once('static NSString *const HFAPCVersion = @"1.2.0";',
     'static NSString *const HFAPCVersion = @"1.2.1-unified";',
     'embedded runtime version')

old_plan = '''typedef struct {\n    uint8_t kind; // 1 capture, 2 pipeline\n    uint8_t slotIndex;\n    mach_vm_address_t address;\n    uint8_t original[HFAPC_RT_ORIGINAL_MAX];\n    uint32_t originalLength;\n    void *replacement;\n} HFAPCRTHookPlan;\n'''
new_plan = '''typedef struct {\n    uint8_t kind; // 1 capture, 2 pipeline\n    uint8_t slotIndex;\n    mach_vm_address_t address;\n    uint8_t original[HFAPC_RT_ORIGINAL_MAX];\n    uint32_t originalLength;\n    uint8_t preexisting[HFAPC_RT_ORIGINAL_MAX];\n    uint32_t preexistingLength;\n    BOOL takeover;\n    void *replacement;\n} HFAPCRTHookPlan;\n'''
once(old_plan, new_plan, 'hook plan takeover fields')

old_preflight = '''        NSData *original = HFAPCHexData(originalHex);\n        if (!original || original.length == 0 || original.length > HFAPC_RT_ORIGINAL_MAX) {\n            if (errorOut) *errorOut = @"runtime-hook-original-invalid";\n            planOK = NO; break;\n        }\n        NSData *current = HFAPCReadMemory(runtime, original.length, errorOut);\n        if (!current || ![current isEqualToData:original]) {\n            if (errorOut && !*errorOut) {\n                *errorOut = [NSString stringWithFormat:@"runtime-hook-preflight-byte-mismatch target=%@ offset=%@ expected=%@ actual=%@",\n                             target, offset, HFAPCHexString(original), HFAPCHexString(current)];\n            }\n            planOK = NO; break;\n        }\n\n        HFAPCRTHookPlan *plan = &plans[planCount];\n        plan->address = runtime;\n        plan->originalLength = (uint32_t)original.length;\n        memcpy(plan->original, original.bytes, original.length);\n'''
new_preflight = '''        NSData *original = HFAPCHexData(originalHex);\n        if (!original || original.length == 0 || original.length > HFAPC_RT_ORIGINAL_MAX) {\n            if (errorOut) *errorOut = @"runtime-hook-original-invalid";\n            planOK = NO; break;\n        }\n\n        HFAPCRTHookPlan *plan = &plans[planCount];\n        plan->address = runtime;\n        plan->originalLength = (uint32_t)original.length;\n        memcpy(plan->original, original.bytes, original.length);\n\n        NSData *current = HFAPCReadMemory(runtime, original.length, errorOut);\n        if (!current) { planOK = NO; break; }\n        if (![current isEqualToData:original]) {\n            NSString *preexistingHex = [hook[@"preexisting"] isKindOfClass:[NSString class]] ? hook[@"preexisting"] : nil;\n            NSData *preexisting = HFAPCHexData(preexistingHex);\n            if (!preexisting || preexisting.length != original.length || ![current isEqualToData:preexisting]) {\n                if (errorOut && !*errorOut) {\n                    *errorOut = [NSString stringWithFormat:@"runtime-hook-preflight-byte-mismatch target=%@ offset=%@ expected=%@ preexisting=%@ actual=%@",\n                                 target, offset, HFAPCHexString(original), preexistingHex ?: @"", HFAPCHexString(current)];\n                }\n                planOK = NO; break;\n            }\n            plan->takeover = YES;\n            plan->preexistingLength = (uint32_t)preexisting.length;\n            memcpy(plan->preexisting, preexisting.bytes, preexisting.length);\n            HFAPCLog(@"[RUNTIME-TAKEOVER] phase=preflight target=%@ offset=%@ status=matched", target, offset);\n        }\n'''
once(old_preflight, new_preflight, 'takeover-aware hook preflight')

install_anchor = '''    for (uint32_t i = 0; i < planCount; i++) {\n        HFAPCRTHookPlan *plan = &plans[i];\n        void **originOut = NULL;\n'''
prepare_block = '''    // If analysis observed a known preexisting hook, replace it only after every\n    // hook passed identity + byte preflight. This makes analyze -> auto-load\n    // possible without blindly stacking Dobby over the original menu backend.\n    uint32_t takeoverPrepared = 0;\n    for (uint32_t i = 0; i < planCount; i++) {\n        HFAPCRTHookPlan *plan = &plans[i];\n        if (!plan->takeover) continue;\n        NSData *originalData = [NSData dataWithBytes:plan->original length:plan->originalLength];\n        NSString *takeoverError = nil;\n        if (!HFAPCWriteMemory(plan->address, originalData, &takeoverError)) {\n            if (errorOut) *errorOut = [NSString stringWithFormat:@"runtime-takeover-restore-original-failed index=%u reason=%@", i, takeoverError ?: @"unknown"];\n            for (uint32_t j = 0; j < i; j++) {\n                HFAPCRTHookPlan *prior = &plans[j];\n                if (!prior->takeover) continue;\n                NSData *oldData = [NSData dataWithBytes:prior->preexisting length:prior->preexistingLength];\n                HFAPCWriteMemory(prior->address, oldData, nil);\n            }\n            for (uint32_t j = 0; j < planCount; j++) HFAPCRTReleaseHookSlot(plans[j].kind, plans[j].slotIndex);\n            graph->inUse = NO;\n            pthread_mutex_unlock(&gHFAPCRTRegistryLock);\n            return NO;\n        }\n        NSData *readback = HFAPCReadMemory(plan->address, plan->originalLength, nil);\n        if (!readback || ![readback isEqualToData:originalData]) {\n            if (errorOut) *errorOut = [NSString stringWithFormat:@"runtime-takeover-original-readback-failed index=%u", i];\n            for (uint32_t j = 0; j <= i; j++) {\n                HFAPCRTHookPlan *prior = &plans[j];\n                if (!prior->takeover) continue;\n                NSData *oldData = [NSData dataWithBytes:prior->preexisting length:prior->preexistingLength];\n                HFAPCWriteMemory(prior->address, oldData, nil);\n            }\n            for (uint32_t j = 0; j < planCount; j++) HFAPCRTReleaseHookSlot(plans[j].kind, plans[j].slotIndex);\n            graph->inUse = NO;\n            pthread_mutex_unlock(&gHFAPCRTRegistryLock);\n            return NO;\n        }\n        takeoverPrepared++;\n        HFAPCLog(@"[RUNTIME-TAKEOVER] phase=restore-original index=%u status=pass", i);\n    }\n\n''' + install_anchor
once(install_anchor, prepare_block, 'takeover prepare before Dobby install')

restore_preexisting = '''            for (uint32_t j = 0; j < planCount; j++) {\n                HFAPCRTHookPlan *oldPlan = &plans[j];\n                if (!oldPlan->takeover) continue;\n                NSData *oldData = [NSData dataWithBytes:oldPlan->preexisting length:oldPlan->preexistingLength];\n                HFAPCWriteMemory(oldPlan->address, oldData, nil);\n            }\n'''

old_install_fail = '''            HFAPCRTReleaseHookSlot(plan->kind, plan->slotIndex);\n            HFAPCRTRollbackGraph(graph);\n            for (uint32_t j = i + 1; j < planCount; j++) HFAPCRTReleaseHookSlot(plans[j].kind, plans[j].slotIndex);\n            graph->inUse = NO;\n'''
new_install_fail = '''            HFAPCRTReleaseHookSlot(plan->kind, plan->slotIndex);\n            HFAPCRTRollbackGraph(graph);\n            for (uint32_t j = i + 1; j < planCount; j++) HFAPCRTReleaseHookSlot(plans[j].kind, plans[j].slotIndex);\n''' + restore_preexisting + '''            graph->inUse = NO;\n'''
once(old_install_fail, new_install_fail, 'install-failure takeover rollback')

old_readback_fail = '''            HFAPCRTRollbackGraph(graph);\n            for (uint32_t j = i + 1; j < planCount; j++) HFAPCRTReleaseHookSlot(plans[j].kind, plans[j].slotIndex);\n            graph->inUse = NO;\n'''
new_readback_fail = '''            HFAPCRTRollbackGraph(graph);\n            for (uint32_t j = i + 1; j < planCount; j++) HFAPCRTReleaseHookSlot(plans[j].kind, plans[j].slotIndex);\n''' + restore_preexisting + '''            graph->inUse = NO;\n'''
once(old_readback_fail, new_readback_fail, 'readback-failure takeover rollback')

once('graph->installedCount, dobbyVersion ? dobbyVersion : "?");',
     'graph->installedCount, dobbyVersion ? dobbyVersion : "?");\n    HFAPCLog(@"[RUNTIME-TAKEOVER] graph=%@ prepared=%u status=active", graphName, takeoverPrepared);',
     'takeover success log')

p.write_text(s)
print('patched embedded runtime with fail-closed preexisting-hook takeover')
