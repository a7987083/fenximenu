from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
UI=Path('hfamap/src/HFAMapCyberUI.m')
s=TRACE.read_text()


def function_span(text, signature):
    start=text.find(signature)
    if start<0: raise SystemExit(f'missing function: {signature}')
    brace=text.find('{',start)
    if brace<0: raise SystemExit(f'missing brace: {signature}')
    depth=0; instr=False; esc=False
    for i in range(brace,len(text)):
        ch=text[i]
        if instr:
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch=='"': instr=False
            continue
        if ch=='"': instr=True; continue
        if ch=='{': depth+=1
        elif ch=='}':
            depth-=1
            if depth==0: return start,i+1
    raise SystemExit(f'unterminated function: {signature}')

for required in ['HFACanonical34Validate','HFACanonical34WriteIdentity','HFAFeatureDefinitionForKey','HFAReadOriginalBytes','HFAReadOriginalBytesFromFile']:
    if required not in s: raise SystemExit('v0312 prerequisite missing '+required)

writer_sig='static void HFAWritePatchPackage(NSArray *features, NSDictionary *targets)'
wa,wb=function_span(s,writer_sig)
helpers=r'''
static NSString *HFA0312AuditDirectory(void) {
    NSBundle *bundle=NSBundle.mainBundle;
    NSString *bundleID=bundle.bundleIdentifier?:@"unknown.game";
    NSString *safe=[bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    NSString *dir=[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:[@"HFAMap_" stringByAppendingString:safe]];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}
static NSDictionary *HFA0312FeatureIdentityForKey(const char *key) {
    if(!key||!*key)return nil;
    HFAFeatureDefinition *d=HFAFeatureDefinitionForKey(key);
    if(d&&d->identifier[0]){
        NSString *fid=[NSString stringWithUTF8String:d->identifier];
        NSString *title=d->label[0]?[NSString stringWithUTF8String:d->label]:fid;
        if(fid.length)return @{@"id":fid,@"title":title?:fid,@"source":@"feature-definition",@"synthetic":@NO};
    }
    NSString *k=[NSString stringWithUTF8String:key];
    if([k hasSuffix:@"-switch"]&&k.length>7){
        NSString *fid=[k substringToIndex:k.length-7];
        if(fid.length)return @{@"id":fid,@"title":fid,@"source":@"descriptor-key-exact",@"synthetic":@YES};
    }
    return nil;
}
static NSUInteger HFA0312PatchCount(NSArray *features){NSUInteger n=0;for(NSDictionary *f in features?:@[]){NSArray *p=[f[@"patches"] isKindOfClass:NSArray.class]?f[@"patches"]:@[];n+=p.count;}return n;}
static void HFA0312AcceptCandidate(NSDictionary *c,NSMutableArray *ledger,NSMutableDictionary *featurePatches,NSMutableDictionary *targets){
    NSUInteger li=[c[@"ledgerIndex"] unsignedIntegerValue];if(li>=ledger.count)return;NSMutableDictionary *le=ledger[li];le[@"status"]=@"exported";le[@"reason"]=@"canonical-static";
    NSString *fid=c[@"featureId"],*tid=c[@"target"],*off=c[@"offset"],*orig=c[@"original"],*en=c[@"enabled"],*image=c[@"image"];
    if(!fid.length||!tid.length||!off.length||!orig.length||!en.length||!image.length)return;
    NSMutableArray *arr=featurePatches[fid];if(!arr){arr=[NSMutableArray array];featurePatches[fid]=arr;}
    [arr addObject:@{@"target":tid,@"offset":off,@"original":orig,@"enabled":en}];targets[tid]=@{@"image":image};
}
static void HFA0312WriteAudit(NSArray *ledger,NSArray *featureDispositions,NSArray *conflicts,NSArray *features,NSDictionary *targets,NSString *packageStatus,NSString *rootPath,NSString *mirrorPath){
    NSString *dir=HFA0312AuditDirectory();NSString *path=[dir stringByAppendingPathComponent:@"HFAMap_StaticCanonical_v0312.json"];
    NSUInteger exported=0,excluded=0,conflicted=0,candidate=0;for(NSDictionary *e in ledger?:@[]){NSString *st=e[@"status"]?:@"";if([st isEqual:@"exported"])exported++;else if([st isEqual:@"conflict"])conflicted++;else if([st isEqual:@"candidate"])candidate++;else excluded++;}
    NSNumber *size=@0;if(rootPath.length&&[[NSFileManager defaultManager] fileExistsAtPath:rootPath]){NSDictionary *a=[[NSFileManager defaultManager] attributesOfItemAtPath:rootPath error:nil];if([a[NSFileSize] isKindOfClass:NSNumber.class])size=a[NSFileSize];}
    NSDictionary *root=@{@"schema":@"com.hfa.static-canonical-audit/v0.3.12",@"policy":@"fail-closed-no-silent-drop",@"packageStatus":packageStatus?:@"unknown",@"packageRootPath":rootPath?:@"",@"packageMirrorPath":mirrorPath?:@"",@"packageSize":size,@"packageFeatureCount":@(features.count),@"packagePatchCount":@(HFA0312PatchCount(features)),@"targetCount":@(targets.count),@"ledgerCount":@(ledger.count),@"exportedCount":@(exported),@"excludedCount":@(excluded),@"conflictCount":@(conflicted),@"candidateCount":@(candidate),@"silentlyDropped":@0,@"ledger":ledger?:@[],@"featureDispositions":featureDispositions?:@[],@"conflicts":conflicts?:@[]};
    NSError *err=nil;NSData *json=[NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:&err];if(json&&[json writeToFile:path options:NSDataWritingAtomic error:&err])HFALog("[STATIC-AUDIT] status=pass path=%s ledger=%u exported=%u excluded=%u conflicts=%u patches=%u\n",path.UTF8String,(unsigned)ledger.count,(unsigned)exported,(unsigned)excluded,(unsigned)conflicted,(unsigned)HFA0312PatchCount(features));else HFALog("[STATIC-AUDIT] status=fail reason=%s\n",err.localizedDescription.UTF8String?:"json");
}
'''

new_writer=r'''static void HFAWritePatchPackage(NSArray *features, NSDictionary *targets, NSArray *ledger, NSArray *featureDispositions, NSArray *conflicts) {
    NSBundle *bundle=NSBundle.mainBundle;NSString *bundleID=bundle.bundleIdentifier?:@"unknown.game";NSString *shortVersion=[bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"]?:@"0";NSString *buildVersion=[bundle objectForInfoDictionaryKey:@"CFBundleVersion"]?:@"0";
    NSString *safeID=[bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];NSString *name=[NSString stringWithFormat:@"%@_%@_%@.hfapatch.json",safeID,shortVersion,buildVersion];NSString *rootPath=[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:name];NSString *mirrorPath=[HFA0312AuditDirectory() stringByAppendingPathComponent:name];NSString *status=@"not-exported";
    if(conflicts.count){HFALog("[CANONICAL-CHECK] status=fail reason=package-conflict conflicts=%u\n",(unsigned)conflicts.count);status=@"blocked-conflict";HFA0312WriteAudit(ledger,featureDispositions,conflicts,features,targets,status,@"",@"");return;}
    if(!HFACanonical34Validate(features,targets)){status=@"validation-failed";HFA0312WriteAudit(ledger,featureDispositions,conflicts,features,targets,status,@"",@"");return;}
    HFACanonical34WriteIdentity(targets);
#ifdef CPU_SUBTYPE_ARM64E
    const struct mach_header *header=_dyld_get_image_header(0);cpu_subtype_t subtype=header?(header->cpusubtype&~CPU_SUBTYPE_MASK):0;NSString *architecture=subtype==CPU_SUBTYPE_ARM64E?@"arm64e":@"arm64";
#else
    NSString *architecture=@"arm64";
#endif
    NSDictionary *root=@{@"schema":@"com.hfa.patch/v1",@"name":[NSString stringWithFormat:@"%@ %@",bundleID,shortVersion],@"package":@{@"bundleIdentifier":bundleID,@"shortVersion":shortVersion,@"buildVersion":buildVersion,@"architectures":@[architecture]},@"targets":targets,@"features":features};NSError *error=nil;NSData *json=[NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:&error];
    if(!json){HFALog("[PACKAGE-EXPORT-FAIL] reason=%s\n",error.localizedDescription.UTF8String?:"json");status=@"json-failed";HFA0312WriteAudit(ledger,featureDispositions,conflicts,features,targets,status,@"",@"");return;}
    BOOL rootOK=[json writeToFile:rootPath options:NSDataWritingAtomic error:&error];if(!rootOK){HFALog("[PACKAGE-EXPORT-FAIL] reason=%s\n",error.localizedDescription.UTF8String?:"write");status=@"root-write-failed";HFA0312WriteAudit(ledger,featureDispositions,conflicts,features,targets,status,@"",@"");return;}
    NSError *mirrorError=nil;BOOL mirrorOK=[json writeToFile:mirrorPath options:NSDataWritingAtomic error:&mirrorError];HFALog("[PACKAGE-EXPORT] path=%s features=%u patches=%u targets=%u\n",rootPath.UTF8String,(unsigned)features.count,(unsigned)HFA0312PatchCount(features),(unsigned)targets.count);
    if(mirrorOK){status=@"exported";HFALog("[PACKAGE-MIRROR] status=pass path=%s\n",mirrorPath.UTF8String);}else{status=@"mirror-failed";HFALog("[PACKAGE-MIRROR] status=fail reason=%s\n",mirrorError.localizedDescription.UTF8String?:"write");}
    HFA0312WriteAudit(ledger,featureDispositions,conflicts,features,targets,status,rootPath,mirrorOK?mirrorPath:@"");
}'''

s=s[:wa]+helpers+'\n'+new_writer+s[wb:]

fa,fb=function_span(s,'unsigned HFAPatchTraceFinalizeScan(void)')
new_finalize=r'''unsigned HFAPatchTraceFinalizeScan(void) {
    NSMutableArray *ledger=[NSMutableArray array],*candidates=[NSMutableArray array],*conflicts=[NSMutableArray array];NSMutableDictionary *featureMeta=[NSMutableDictionary dictionary],*featurePatches=[NSMutableDictionary dictionary],*exportTargets=[NSMutableDictionary dictionary];NSMutableSet *groupKeys=[NSMutableSet set];unsigned validParts=0;
    for(unsigned i=0;i<gFeatureDefinitionCount;i++){HFAFeatureDefinition *d=&gFeatureDefinitions[i];if(!d->identifier[0])continue;NSString *fid=[NSString stringWithUTF8String:d->identifier];if(!fid.length)continue;NSString *title=d->label[0]?[NSString stringWithUTF8String:d->label]:fid;featureMeta[fid]=@{@"id":fid,@"title":title?:fid,@"source":@"feature-definition",@"synthetic":@NO};}
    HFALog("[V0312-STATIC-BEGIN] definitions=%u descriptors=%u\n",gFeatureDefinitionCount,gDescriptorCount);
    for(unsigned i=0;i<gDescriptorCount;i++){@autoreleasepool{HFADescriptor *d=&gDescriptors[i];NSMutableDictionary *e=[NSMutableDictionary dictionary];e[@"descriptorIndex"]=@(i);NSString *key=d->key[0]?[NSString stringWithUTF8String:d->key]:@"";e[@"key"]=key;e[@"sourceImage"]=d->sourceImage[0]?[NSString stringWithUTF8String:d->sourceImage]:@"";e[@"module"]=d->module[0]?[NSString stringWithUTF8String:d->module]:@"";if(key.length)[groupKeys addObject:key];
        NSDictionary *ident=d->key[0]?HFA0312FeatureIdentityForKey(d->key):nil;if(ident){NSString *fid=ident[@"id"];e[@"featureId"]=fid;e[@"title"]=ident[@"title"]?:fid;e[@"ownershipSource"]=ident[@"source"]?:@"unknown";e[@"syntheticOwnership"]=ident[@"synthetic"]?:@NO;if(fid.length&&!featureMeta[fid])featureMeta[fid]=ident;}
        char off[160]={0},norm[164]={0},patch[512]={0};int haveOffset=HFADecryptWrapper(d->offsetWrapper,off,sizeof(off),"v0312-offset");int havePatch=HFADecryptWrapper(d->patchWrapper,patch,sizeof(patch),"v0312-patchData");if(haveOffset&&off[0]=='0'&&(off[1]=='x'||off[1]=='X'))snprintf(norm,sizeof(norm),"%s",off);else if(haveOffset&&HFAValidOffset(off))snprintf(norm,sizeof(norm),"0x%s",off);if(norm[0])e[@"offset"]=[NSString stringWithUTF8String:norm];if(havePatch)e[@"enabled"]=[NSString stringWithUTF8String:patch];
        BOOL mappingValid=haveOffset&&havePatch&&HFAValidOffset(off)&&HFAValidPatch(patch)&&d->module[0];if(mappingValid)validParts++;
        if(!key.length){e[@"status"]=@"excluded";e[@"reason"]=@"no-feature-key";[ledger addObject:e];continue;}
        if(!ident){e[@"status"]=@"excluded";e[@"reason"]=@"no-feature-owner";[ledger addObject:e];continue;}
        if(!mappingValid){e[@"status"]=@"excluded";if(!d->module[0])e[@"reason"]=@"target-module-missing";else if(!haveOffset||!HFAValidOffset(off))e[@"reason"]=@"offset-invalid";else e[@"reason"]=@"enabled-bytes-invalid";[ledger addObject:e];continue;}
        int imageIndex=HFAImageIndexForName(d->module);if(imageIndex<0){e[@"status"]=@"excluded";e[@"reason"]=@"target-image-not-loaded";[ledger addObject:e];continue;}NSData *enabled=HFADataFromHex(patch);uint64_t rva=strtoull(norm,NULL,16);const char *originalSource="unavailable";int originalCryptid=-1;NSData *original=enabled.length?HFAReadOriginalBytes((uint32_t)imageIndex,rva,enabled.length,&originalSource,&originalCryptid):nil;if(enabled.length&&original.length==enabled.length&&[original isEqualToData:enabled]){int fileCryptid=-1;NSData *fileOriginal=HFAReadOriginalBytesFromFile((uint32_t)imageIndex,rva,enabled.length,&fileCryptid);if(fileOriginal.length==enabled.length&&![fileOriginal isEqualToData:enabled]){original=fileOriginal;originalSource="mach-o-file-after-enabled-live";originalCryptid=fileCryptid;}}e[@"originalSource"]=[NSString stringWithUTF8String:originalSource?:"unavailable"];e[@"cryptid"]=@(originalCryptid);if(!enabled.length||original.length!=enabled.length){e[@"status"]=@"excluded";e[@"reason"]=@"original-bytes-unavailable";[ledger addObject:e];continue;}NSString *origHex=HFAHexData(original),*enHex=[NSString stringWithUTF8String:patch];e[@"original"]=origHex;if([original isEqualToData:enabled]){e[@"status"]=@"excluded";e[@"reason"]=@"patch-already-enabled";[ledger addObject:e];continue;}
        NSString *fid=ident[@"id"],*tid=imageIndex==0?@"main":[NSString stringWithUTF8String:d->module],*image=imageIndex==0?@"@main":[NSString stringWithUTF8String:HFABase(_dyld_get_image_name((uint32_t)imageIndex))];e[@"target"]=tid;e[@"status"]=@"candidate";e[@"reason"]=@"awaiting-conflict-audit";NSUInteger li=ledger.count;[ledger addObject:e];[candidates addObject:@{@"ledgerIndex":@(li),@"featureId":fid,@"target":tid,@"image":image,@"offset":[NSString stringWithUTF8String:norm],@"original":origHex,@"enabled":enHex}];
    }}
    NSMutableDictionary *byTarget=[NSMutableDictionary dictionary];for(NSDictionary *c in candidates){NSString *k=[NSString stringWithFormat:@"%@|%@",c[@"target"]?:@"?",c[@"offset"]?:@"?"];NSMutableArray *a=byTarget[k];if(!a){a=[NSMutableArray array];byTarget[k]=a;}[a addObject:c];}
    NSArray *targetKeys=[[byTarget allKeys] sortedArrayUsingSelector:@selector(compare:)];for(NSString *tk in targetKeys){NSArray *group=byTarget[tk];if(group.count==1){HFA0312AcceptCandidate(group.firstObject,ledger,featurePatches,exportTargets);continue;}NSMutableSet *fids=[NSMutableSet set],*sigs=[NSMutableSet set];for(NSDictionary *c in group){[fids addObject:c[@"featureId"]?:@"?"];[sigs addObject:[NSString stringWithFormat:@"%@|%@",c[@"original"]?:@"",c[@"enabled"]?:@""]];}
        if(fids.count==1&&sigs.count==1){HFA0312AcceptCandidate(group.firstObject,ledger,featurePatches,exportTargets);for(NSUInteger n=1;n<group.count;n++){NSUInteger li=[group[n][@"ledgerIndex"] unsignedIntegerValue];if(li<ledger.count){NSMutableDictionary *le=ledger[li];le[@"status"]=@"excluded";le[@"reason"]=@"duplicate-identical-same-feature";}}continue;}
        NSMutableArray *ids=[NSMutableArray array];for(NSDictionary *c in group){NSUInteger li=[c[@"ledgerIndex"] unsignedIntegerValue];if(li<ledger.count){NSMutableDictionary *le=ledger[li];le[@"status"]=@"conflict";le[@"reason"]=fids.count>1?@"shared-target-multiple-features":@"duplicate-target-different-bytes";}[ids addObject:c[@"featureId"]?:@"?"];}
        NSArray *parts=[tk componentsSeparatedByString:@"|"];NSDictionary *conf=@{@"target":parts.firstObject?:@"?",@"offset":parts.count>1?parts[1]:@"?",@"featureIds":ids,@"reason":fids.count>1?@"shared-target-multiple-features":@"duplicate-target-different-bytes",@"status":@"blocked"};[conflicts addObject:conf];HFALog("[STATIC-CONFLICT] target=%s offset=%s features=%u reason=%s\n",[conf[@"target"] UTF8String]?:"?",[conf[@"offset"] UTF8String]?:"?",(unsigned)ids.count,[conf[@"reason"] UTF8String]?:"?");
    }
    NSMutableArray *exportFeatures=[NSMutableArray array];NSArray *fids=[[featurePatches allKeys] sortedArrayUsingSelector:@selector(compare:)];for(NSString *fid in fids){NSArray *patches=featurePatches[fid];if(!patches.count)continue;NSDictionary *meta=featureMeta[fid]?:@{};NSString *title=[meta[@"title"] isKindOfClass:NSString.class]?meta[@"title"]:fid;[exportFeatures addObject:@{@"id":fid,@"title":title?:fid,@"group":@"Imported",@"defaultEnabled":@NO,@"patches":patches}];}
    NSMutableArray *featureDispositions=[NSMutableArray array];NSArray *allFeatures=[[featureMeta allKeys] sortedArrayUsingSelector:@selector(compare:)];for(NSString *fid in allFeatures){NSUInteger desc=0,exp=0,exc=0,con=0;for(NSDictionary *e in ledger){if(![e[@"featureId"] isEqual:fid])continue;desc++;NSString *st=e[@"status"]?:@"";if([st isEqual:@"exported"])exp++;else if([st isEqual:@"conflict"])con++;else exc++;}NSDictionary *meta=featureMeta[fid];NSString *status=con?@"conflict":(exp?@"exported":@"excluded");NSString *reason=con?@"target-conflict":(exp?@"canonical-static":(desc?@"all-descriptors-excluded":@"no-static-descriptor"));NSDictionary *fd=@{@"id":fid,@"title":meta[@"title"]?:fid,@"ownershipSource":meta[@"source"]?:@"unknown",@"status":status,@"reason":reason,@"descriptorCount":@(desc),@"exportedPatchCount":@(exp),@"excludedCount":@(exc),@"conflictCount":@(con)};[featureDispositions addObject:fd];HFALog("[STATIC-DISPOSITION] feature=%s status=%s descriptors=%u exported=%u excluded=%u conflicts=%u reason=%s\n",fid.UTF8String?:"?",status.UTF8String?:"?",(unsigned)desc,(unsigned)exp,(unsigned)exc,(unsigned)con,reason.UTF8String?:"?");}
    NSUInteger exported=0,excluded=0,conflicted=0;for(NSDictionary *e in ledger){NSString *st=e[@"status"]?:@"";if([st isEqual:@"exported"])exported++;else if([st isEqual:@"conflict"])conflicted++;else excluded++;HFALog("[STATIC-LEDGER] descriptor=%u feature=%s key=%s target=%s offset=%s status=%s reason=%s\n",(unsigned)[e[@"descriptorIndex"] unsignedIntegerValue],[e[@"featureId"] UTF8String]?:"?",[e[@"key"] UTF8String]?:"?",[e[@"target"] UTF8String]?:"?",[e[@"offset"] UTF8String]?:"?",[e[@"status"] UTF8String]?:"?",[e[@"reason"] UTF8String]?:"?");}
    HFALog("[FULL-SCAN-END] groups=%u mappings=%u valid=%u unresolved=%u\n",(unsigned)groupKeys.count,gDescriptorCount,validParts,gDescriptorCount-validParts);HFALog("[V0312-STATIC-CANONICAL] ledger=%u candidates=%u exported=%u excluded=%u conflicts=%u packageFeatures=%u packagePatches=%u\n",(unsigned)ledger.count,(unsigned)candidates.count,(unsigned)exported,(unsigned)excluded,(unsigned)conflicted,(unsigned)exportFeatures.count,(unsigned)HFA0312PatchCount(exportFeatures));HFAWritePatchPackage(exportFeatures,exportTargets,ledger,featureDispositions,conflicts);return validParts;
}'''
s=s[:fa]+new_finalize+s[fb:]
TRACE.write_text(s)

ui=UI.read_text()
ui=ui.replace('HFAMap RuntimeAnalyzer v0.3.11 ADRFullTextXrefConsumer','HFAMap RuntimeAnalyzer v0.3.12 StaticCanonicalCompletion')
UI.write_text(ui)

out=TRACE.read_text()
for req in ['HFA0312FeatureIdentityForKey','descriptor-key-exact','[STATIC-LEDGER]','[STATIC-DISPOSITION]','[STATIC-CONFLICT]','[STATIC-AUDIT]','[PACKAGE-MIRROR]','[V0312-STATIC-CANONICAL]','HFAMap_StaticCanonical_v0312.json','fail-closed-no-silent-drop','originalSource','mach-o-file-after-enabled-live']:
    if req not in out: raise SystemExit('v0312 missing '+req)
if 'HFAWritePatchPackage(exportFeatures,exportTargets,ledger,featureDispositions,conflicts)' not in out:
    raise SystemExit('v0312 package bridge missing')
print('v0.3.12 static canonical completion applied')
