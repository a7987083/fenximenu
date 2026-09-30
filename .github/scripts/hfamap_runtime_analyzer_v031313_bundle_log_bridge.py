from pathlib import Path

P=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
s=P.read_text()
anchor='''if([runtimeTruth isKindOfClass:[NSDictionary class]]){\n        NSMutableDictionary *truthRoot=[root mutableCopy];truthRoot[@"runtimeModificationTruth"]=runtimeTruth;root=truthRoot;'''
if anchor not in s: raise SystemExit('runtime truth bundle-log anchor missing')
bridge=r'''if([runtimeTruth isKindOfClass:[NSDictionary class]]){
        for(NSDictionary *p in [runtimeTruth[@"patches"] isKindOfClass:NSArray.class]?runtimeTruth[@"patches"]:@[]){
            HFALog("[V031313-PATCH-STATE] backend=%s owner=%s feature=%s target=%s+%s state=%s bytes=%s\\n",
                   [[p[@"analyzerBackendId"] description] UTF8String]?:"?",[[p[@"ownerClass"] description] UTF8String]?:"?",[[p[@"featureId"] description] UTF8String]?:"?",[[p[@"targetImage"] description] UTF8String]?:"?",[[p[@"targetRVA"] description] UTF8String]?:"?",[[p[@"state"] description] UTF8String]?:"?",[[p[@"runtimeBytes"] description] UTF8String]?:"");
        }
        for(NSDictionary *h in [runtimeTruth[@"runtimeHooks"] isKindOfClass:NSArray.class]?runtimeTruth[@"runtimeHooks"]:@[]){
            NSDictionary *op=[h[@"originalPointer"] isKindOfClass:NSDictionary.class]?h[@"originalPointer"]:@{};
            HFALog("[V031313-HOOK-STATE] backend=%s target=%s+%s replacement=%s+%s slot=%s original=%s installed=%u semantic=%s\\n",
                   [[h[@"backendId"] description] UTF8String]?:"?",[[h[@"targetImage"] description] UTF8String]?:"?",[[h[@"targetRVA"] description] UTF8String]?:"?",[[h[@"replacementImage"] description] UTF8String]?:"?",[[h[@"replacementRVA"] description] UTF8String]?:"?",[[h[@"originalSlotRVA"] description] UTF8String]?:"?",[[op[@"address"] description] UTF8String]?:"0x0",[h[@"installed"] boolValue]?1:0,[[h[@"semanticType"] description] UTF8String]?:"?");
        }
        HFALog("[V031313-TRUTH-SUMMARY] menu=%u startup=%u startupMods=%u effective=%u patchSites=%u hooks=%u installedHooks=%u enabled=%u original=%u unknown=%u unreadable=%u\\n",
               [runtimeTruth[@"menuFeatureCount"] unsignedIntValue],[runtimeTruth[@"startupFeatureCount"] unsignedIntValue],[runtimeTruth[@"startupModificationCount"] unsignedIntValue],[runtimeTruth[@"effectiveFeatureCount"] unsignedIntValue],[runtimeTruth[@"fixedPatchSiteCount"] unsignedIntValue],[runtimeTruth[@"runtimeHookCount"] unsignedIntValue],[runtimeTruth[@"installedHookCount"] unsignedIntValue],[runtimeTruth[@"enabledPatchCount"] unsignedIntValue],[runtimeTruth[@"originalPatchCount"] unsignedIntValue],[runtimeTruth[@"unknownPatchCount"] unsignedIntValue],[runtimeTruth[@"unreadablePatchCount"] unsignedIntValue]);
        NSMutableDictionary *truthRoot=[root mutableCopy];truthRoot[@"runtimeModificationTruth"]=runtimeTruth;root=truthRoot;'''
s=s.replace(anchor,bridge,1)
P.write_text(s)
for token in ['[V031313-PATCH-STATE]','[V031313-HOOK-STATE]','[V031313-TRUTH-SUMMARY]','startupMods=%u']:
    if token not in s: raise SystemExit('bundle log bridge missing '+token)
print('v0.3.13.13 bundle log bridge applied')
