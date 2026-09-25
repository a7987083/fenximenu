from pathlib import Path

ROOT = Path('hfamap')
V02 = ROOT / 'src/HFAMapRuntimeAnalyzerV02.m'


def function_span(text, name):
    needle = name + '('
    pos = 0
    while True:
        i = text.find(needle, pos)
        if i < 0:
            raise SystemExit(f'{name}: function not found')
        start = text.rfind('\n', 0, i) + 1
        brace = text.find('{', i)
        semi = text.find(';', i)
        if brace >= 0 and (semi < 0 or brace < semi):
            depth = 0
            in_str = False
            esc = False
            for j in range(brace, len(text)):
                ch = text[j]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == '\\':
                        esc = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                    continue
                if ch == '{': depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0: return start, j + 1
        pos = i + len(needle)


def replace_fn(text, name, replacement):
    a, b = function_span(text, name)
    return text[:a] + replacement + text[b:]

s = V02.read_text()

kind = r'''static NSString *HFAV02Kind(uint32_t fam,NSString *p){
    if(fam==0x031201u||fam==0x031211u)return @"target-rva";
    if(fam==0x021401u||fam==0x021411u)return @"patch-data";
    if(fam==0x000101u)return @"generic-string";
    if([p hasPrefix:@"0x"]&&p.length>3)return @"string-rva-like";
    return @"unknown";
}'''
s = replace_fn(s, 'HFAV02Kind', kind)

helpers = r'''
static BOOL HFAV032TargetFamily(uint32_t f){return f==0x031201u||f==0x031211u;}
static BOOL HFAV032PatchFamily(uint32_t f){return f==0x021401u||f==0x021411u;}
static uint64_t HFAV032HexValue(NSString *s,BOOL *ok){
    if(ok)*ok=NO;if(![s isKindOfClass:[NSString class]]||!s.length)return 0;
    const char *p=s.UTF8String;if(!p)return 0;if(p[0]=='0'&&(p[1]=='x'||p[1]=='X'))p+=2;
    if(!*p)return 0;char *e=NULL;unsigned long long v=strtoull(p,&e,16);
    if(!e||*e)return 0;if(ok)*ok=YES;return (uint64_t)v;
}
static NSData *HFAV032HexData(NSString *s){
    if(![s isKindOfClass:[NSString class]]||!s.length||s.length>128||(s.length&1))return nil;
    NSMutableData *d=[NSMutableData dataWithCapacity:s.length/2];const char *p=s.UTF8String;
    for(NSUInteger i=0;i<s.length;i+=2){char t[3]={p[i],p[i+1],0};char *e=NULL;unsigned long v=strtoul(t,&e,16);if(!e||*e)return nil;uint8_t b=(uint8_t)v;[d appendBytes:&b length:1];}
    return d;
}
static NSString *HFAV032HexBytes(const void *p,NSUInteger n){
    if(!p||!n)return @"";const uint8_t *b=(const uint8_t*)p;NSMutableString *s=[NSMutableString stringWithCapacity:n*2];for(NSUInteger i=0;i<n;i++)[s appendFormat:@"%02X",b[i]];return s;
}
static NSString *HFAV032UUID(const struct mach_header_64 *h){
    if(!h)return @"unknown";const uint8_t *c=(const uint8_t*)(h+1);for(uint32_t i=0;i<h->ncmds;i++){const struct load_command *lc=(const struct load_command*)c;if(!lc->cmdsize)break;if(lc->cmd==LC_UUID){const struct uuid_command *u=(const struct uuid_command*)c;const uint8_t *x=u->uuid;return [NSString stringWithFormat:@"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",x[0],x[1],x[2],x[3],x[4],x[5],x[6],x[7],x[8],x[9],x[10],x[11],x[12],x[13],x[14],x[15]];}c+=lc->cmdsize;}return @"unknown";
}
static BOOL HFAV032Writable(uintptr_t a,HFAV02Layout l){
    const struct mach_header_64 *h=(const struct mach_header_64*)l.base;if(!h)return NO;const uint8_t *c=(const uint8_t*)(h+1);
    for(uint32_t i=0;i<h->ncmds;i++){const struct load_command *lc=(const struct load_command*)c;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *g=(const struct segment_command_64*)c;uintptr_t s=(uintptr_t)l.slide+(uintptr_t)g->vmaddr,e=s+(uintptr_t)g->vmsize;if(a>=s&&a<e)return (g->initprot&2)!=0;}c+=lc->cmdsize;}return NO;
}
static NSDictionary *HFAV032ResolveTarget(uint64_t preferred,const char *menuImage){
    NSString *bundle=[NSBundle mainBundle].bundlePath?:@"";NSMutableArray *hits=[NSMutableArray array];uint32_t n=_dyld_image_count();
    for(uint32_t i=0;i<n;i++){@autoreleasepool{const char *cp=_dyld_get_image_name(i);if(!cp)continue;NSString *path=[NSString stringWithUTF8String:cp]?:@"";if(bundle.length&&![path hasPrefix:bundle])continue;NSString *bn=path.lastPathComponent.lowercaseString;if([bn containsString:@"hfamap"]||[bn containsString:@"runtimeanalyzer"])continue;const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header(i);if(!h||h->magic!=MH_MAGIC_64)continue;intptr_t slide=_dyld_get_image_vmaddr_slide(i);uint64_t base=UINT64_MAX;BOOL contains=NO;const uint8_t *c=(const uint8_t*)(h+1);for(uint32_t k=0;k<h->ncmds;k++){const struct load_command *lc=(const struct load_command*)c;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *g=(const struct segment_command_64*)c;if(strcmp(g->segname,"__PAGEZERO")&&g->vmsize&&g->vmaddr<base)base=g->vmaddr;if((g->initprot&4)&&preferred>=g->vmaddr&&preferred<g->vmaddr+g->vmsize)contains=YES;}c+=lc->cmdsize;}if(!contains)continue;if(base==UINT64_MAX)base=0;[hits addObject:@{@"image":path.lastPathComponent?:@"?",@"path":path,@"uuid":HFAV032UUID(h),@"targetRVA":[NSString stringWithFormat:@"0x%llX",preferred-base],@"preferredVMAddress":[NSString stringWithFormat:@"0x%llX",preferred],@"runtimeAddress":@((unsigned long long)((int64_t)preferred+slide))}];}}
    if(hits.count!=1)return @{ @"status":hits.count?@"ambiguous":@"not-found",@"candidateCount":@(hits.count),@"candidates":hits };
    NSMutableDictionary *r=[hits.firstObject mutableCopy];r[@"status"]=@"unique";r[@"candidateCount"]=@1;return r;
}
static BOOL HFAV032Cond(uint32_t w){return (w&0x7E000000u)==0x34000000u||(w&0xFF000010u)==0x54000000u||(w&0x7E000000u)==0x36000000u;}
static BOOL HFAV032MoveWide32(uint32_t w,uint32_t *vals,BOOL *known){unsigned r=w&31u,sh=((w>>21)&3u)*16u,imm=(w>>5)&0xFFFFu;if((w&0x7F800000u)==0x52800000u){vals[r]=imm<<sh;known[r]=YES;return YES;}if((w&0x7F800000u)==0x72800000u&&known[r]){uint32_t m=0xFFFFu<<sh;vals[r]=(vals[r]&~m)|(imm<<sh);return YES;}return NO;}
static BOOL HFAV032StoreX0(uint32_t w,unsigned *rn,uint64_t *off){
    if((w&0xFFFFFC1Fu)==0xC89FFC00u||(w&0xFFFFFC1Fu)==0x889FFC00u){if(rn)*rn=(w>>5)&31u;if(off)*off=0;return YES;}
    if((w&0xFFC0001Fu)==0xF9000000u){if(rn)*rn=(w>>5)&31u;if(off)*off=((w>>10)&0xFFFu)*8u;return YES;}
    if((w&0xFFC0001Fu)==0xB9000000u){if(rn)*rn=(w>>5)&31u;if(off)*off=((w>>10)&0xFFFu)*4u;return YES;}
    return NO;
}
static NSDictionary *HFAV032ReplacementSemantics(uintptr_t repl,uintptr_t originalSlot,HFAV02Layout l){
    if(!repl||repl<l.text.start||repl>=l.text.end)return @{};const uint32_t *w=(const uint32_t*)repl;NSUInteger n=MIN((NSUInteger)192,(NSUInteger)((l.text.end-repl)/4));uintptr_t addr[32]={0};BOOL ak[32]={0};uint32_t vals[32]={0};BOOL vk[32]={0};BOOL cond=NO;NSMutableOrderedSet *fields=[NSMutableOrderedSet orderedSet];NSMutableOrderedSet *states=[NSMutableOrderedSet orderedSet];uintptr_t receiver=0;
    for(NSUInteger i=0;i<n;i++){uintptr_t pc=repl+i*4;unsigned r=0;uintptr_t v=0;NSUInteger used=0;if(HFAV03Materialize(w,n,i,pc,&r,&v,&used)){addr[r]=v;ak[r]=YES;if(HFAV032Writable(v,l)&&v!=originalSlot)[states addObject:[NSString stringWithFormat:@"0x%llX",(unsigned long long)(v-l.base)]];}
        uint32_t x=w[i];if(HFAV032Cond(x))cond=YES;if(HFAV032MoveWide32(x,vals,vk))continue;
        if((x&0xFFC00000u)==0xB9000000u){unsigned vr=x&31u,br=(x>>5)&31u;uint32_t fo=((x>>10)&0xFFFu)*4u;if(cond&&vk[vr]&&br!=31u&&fo>=4&&fo<=0x4000u)[fields addObject:[NSString stringWithFormat:@"0x%X",fo]];}
        unsigned br=0;uint64_t of=0;if(!receiver&&HFAV032StoreX0(x,&br,&of)&&ak[br]){uintptr_t dst=addr[br]+of;if(HFAV032Writable(dst,l)&&dst!=originalSlot)receiver=dst;}
    }
    if(receiver)[states removeObject:[NSString stringWithFormat:@"0x%llX",(unsigned long long)(receiver-l.base)]];
    NSString *type=receiver?@"receiver-capture":(states.count?@"runtime-state":@"direct-native-hook");return @{@"semanticType":type,@"receiverStoreRVA":receiver?[NSString stringWithFormat:@"0x%llX",(unsigned long long)(receiver-l.base)]:@"",@"fieldOffsets":fields.array,@"runtimeStateCandidates":states.array};
}
static BOOL HFAV032LdrS(uint32_t w,uint32_t *field,unsigned *vr,unsigned *br){if((w&0xFFC00000u)!=0xBD400000u)return NO;if(field)*field=((w>>10)&0xFFFu)*4u;if(vr)*vr=w&31u;if(br)*br=(w>>5)&31u;return YES;}
static BOOL HFAV032FsubS(uint32_t w,unsigned vr){return (w&0xFFE0FC00u)==0x1E203800u&&(w&31u)==vr&&((w>>5)&31u)==vr;}
static BOOL HFAV032StrS(uint32_t w,uint32_t field,unsigned vr,unsigned br){return (w&0xFFC00000u)==0xBD000000u&&(((w>>10)&0xFFFu)*4u)==field&&(w&31u)==vr&&((w>>5)&31u)==br;}
static NSArray *HFAV032FieldConsumers(NSArray *fieldStrings,const char *menuImage){
    if(!fieldStrings.count)return @[];NSMutableSet *fields=[NSMutableSet set];for(NSString *x in fieldStrings){BOOL ok=NO;uint64_t f=HFAV032HexValue(x,&ok);if(ok&&f<=0x4000)[fields addObject:@((uint32_t)f)];}if(!fields.count)return @[];NSString *bundle=[NSBundle mainBundle].bundlePath?:@"";NSMutableArray *out=[NSMutableArray array];uint64_t scanned=0,maxScan=384ULL*1024ULL*1024ULL;NSTimeInterval deadline=[NSDate date].timeIntervalSince1970+2.0;uint32_t n=_dyld_image_count();
    for(uint32_t i=0;i<n&&[NSDate date].timeIntervalSince1970<deadline&&scanned<maxScan;i++){@autoreleasepool{const char *cp=_dyld_get_image_name(i);if(!cp)continue;NSString *path=[NSString stringWithUTF8String:cp]?:@"";if(bundle.length&&![path hasPrefix:bundle])continue;NSString *name=path.lastPathComponent?:@"?";if(menuImage&&[name isEqualToString:[NSString stringWithUTF8String:menuImage]])continue;NSString *low=name.lowercaseString;if([low containsString:@"hfamap"]||[low containsString:@"runtimeanalyzer"])continue;const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header(i);if(!h||h->magic!=MH_MAGIC_64)continue;intptr_t slide=_dyld_get_image_vmaddr_slide(i);NSString *uuid=HFAV032UUID(h);const uint8_t *c=(const uint8_t*)(h+1);for(uint32_t k=0;k<h->ncmds&&[NSDate date].timeIntervalSince1970<deadline&&scanned<maxScan;k++){const struct load_command *lc=(const struct load_command*)c;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *g=(const struct segment_command_64*)c;if((g->initprot&4)&&g->vmsize&&g->vmsize<=192ULL*1024ULL*1024ULL){uint64_t bytes=MIN(g->vmsize,maxScan-scanned);uintptr_t rs=(uintptr_t)((int64_t)g->vmaddr+slide);for(uint64_t off=0;off+48<=bytes;off+=4){const uint32_t *q=(const uint32_t*)(rs+off);uint32_t field=0;unsigned vr=0,br=0;if(!HFAV032LdrS(q[0],&field,&vr,&br)||![fields containsObject:@(field)]||br==31u)continue;for(unsigned a=1;a<=9;a++){if(off+a*4+20>bytes)break;if(!HFAV032FsubS(q[a],vr))continue;for(unsigned z=a+1;z<=a+4;z++){if(!HFAV032StrS(q[z],field,vr,br))continue;uint64_t prva=g->vmaddr+off+a*4;[out addObject:@{@"targetImage":name,@"targetUUID":uuid,@"fieldOffset":[NSString stringWithFormat:@"0x%X",field],@"patchRVA":[NSString stringWithFormat:@"0x%llX",prva],@"baseRegister":@(br),@"original":HFAV032HexBytes(&q[a],4),@"enabled":@"1F2003D5"}];break;}break;}}scanned+=bytes;}}c+=lc->cmdsize;}}}
    if(out.count<=1)return out;NSMutableArray *unique=[NSMutableArray array];for(NSDictionary *a in out){NSUInteger same=0;for(NSDictionary *b in out)if([a[@"fieldOffset"] isEqual:b[@"fieldOffset"]])same++;if(same==1)[unique addObject:a];}return unique.count?unique:out;
}
'''

anchor = 'unsigned HFAAnalyzerV02ScanSelectedImage(void)'
idx = s.find(anchor)
if idx < 0: raise SystemExit('scan anchor missing')
if 'HFAV032TargetFamily' not in s:
    s = s[:idx] + helpers + '\n' + s[idx:]

scan = r'''unsigned HFAAnalyzerV02ScanSelectedImage(void){@autoreleasepool{
    const char *image=HFAAppLocalPrimaryImage();if(!image||!*image){HFAV02Log(@"[V032-SCAN] status=no-selected-image");return 0;}
    NSMutableArray<NSValue*> *ranges=[NSMutableArray array];HFAV02Layout l={0};if(!HFAV02LayoutForImage(image,&l,ranges)){HFAV02Log(@"[V032-SCAN] status=no-layout");return 0;}
    uintptr_t decrypt=HFAV02ResolveDecrypt(image,l);if(!decrypt){HFAV02Log([NSString stringWithFormat:@"[V032-SCAN] image=%s status=no-decrypt",image]);return 0;}
    NSMutableArray *records=[NSMutableArray array];unsigned targets=0,patches=0,generic=0;
    for(NSValue *v in ranges){HFAV02Range r={0};[v getValue:&r];for(uintptr_t p=r.start;p+0x30<=r.end;p+=4){uint32_t len=0,flags=0;memcpy(&len,(void*)p,4);memcpy(&flags,(void*)(p+4),4);unsigned keyId=flags>>24,fam=flags&0x00FFFFFFu;if(!len||len>0x200||keyId>63)continue;if(!HFAV032TargetFamily(fam)&&!HFAV032PatchFamily(fam)&&fam!=0x000101u)continue;size_t blob=(size_t)(len&~0xFu)+0x28u;if(blob<0x28)blob=0x28;if(p+blob>r.end)continue;void *copy=malloc(blob),*plain=calloc(1,len+0x20);if(!copy||!plain){free(copy);free(plain);continue;}memcpy(copy,(void*)p,blob);int rc=((HFASecretDecryptFn)decrypt)(copy,plain);if(rc){free(copy);free(plain);continue;}char buf[0x241]={0};unsigned nc=MIN(len,(uint32_t)0x240);memcpy(buf,plain,nc);free(copy);free(plain);if(!HFAV02Printable(buf,nc))continue;NSString *pt=[NSString stringWithUTF8String:buf]?:@"";NSString *kind=HFAV02Kind(fam,pt);if(HFAV032TargetFamily(fam))targets++;else if(HFAV032PatchFamily(fam))patches++;else generic++;uintptr_t repl=0,slot=0;NSArray *xrefs=HFAV02Xrefs(p,l,&repl,&slot);NSMutableDictionary *rec=[@{@"descriptorRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(p-l.base)],@"descriptorRVAValue":@((unsigned long long)(p-l.base)),@"blobSize":@((unsigned long long)blob),@"keyId":@(keyId),@"family":[NSString stringWithFormat:@"0x%06X",fam],@"familyValue":@(fam),@"kind":kind,@"plain":pt,@"xrefs":xrefs?:@[]} mutableCopy];if(repl)rec[@"replacementRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(repl-l.base)];if(slot)rec[@"originalSlotRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(slot-l.base)];[records addObject:rec];}}
    [records sortUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){return [a[@"descriptorRVAValue"] compare:b[@"descriptorRVAValue"]];}];
    NSMutableArray *backends=[NSMutableArray array];NSMutableSet *pairedPatch=[NSMutableSet set];unsigned backendId=0,nativeCount=0,staticCount=0,receiverCount=0,stateCount=0,derivedCount=0;
    for(NSUInteger i=0;i<records.count;i++){NSDictionary *r=records[i];uint32_t fam=[r[@"familyValue"] unsignedIntValue];if(!HFAV032TargetFamily(fam))continue;backendId++;uint64_t desc=[r[@"descriptorRVAValue"] unsignedLongLongValue],blob=[r[@"blobSize"] unsignedLongLongValue];NSDictionary *next=i+1<records.count?records[i+1]:nil;BOOL paired=NO;if(next&&HFAV032PatchFamily([next[@"familyValue"] unsignedIntValue])&&[next[@"descriptorRVAValue"] unsignedLongLongValue]==desc+blob&&[next[@"keyId"] unsignedIntValue]==[r[@"keyId"] unsignedIntValue])paired=YES;
        NSMutableDictionary *b=[@{@"backendId":@(backendId),@"descriptorRVA":r[@"descriptorRVA"],@"keyId":r[@"keyId"],@"family":r[@"family"],@"targetPlain":r[@"plain"],@"xrefs":r[@"xrefs"]?:@[]} mutableCopy];BOOL tok=NO;uint64_t preferred=HFAV032HexValue(r[@"plain"],&tok);NSDictionary *target=tok?HFAV032ResolveTarget(preferred,image):@{@"status":@"invalid-target-plaintext"};b[@"targetResolution"]=target;if([target[@"status"] isEqual:@"unique"]){b[@"targetImage"]=target[@"image"];b[@"targetUUID"]=target[@"uuid"];b[@"targetRVA"]=target[@"targetRVA"];}
        if(paired){staticCount++;b[@"backendType"]=@"static-patch";b[@"patchDescriptorRVA"]=next[@"descriptorRVA"];b[@"enabled"]=next[@"plain"];[pairedPatch addObject:next[@"descriptorRVA"]];NSData *pd=HFAV032HexData(next[@"plain"]);if(pd.length&&[target[@"status"] isEqual:@"unique"]){uintptr_t ra=(uintptr_t)[target[@"runtimeAddress"] unsignedLongLongValue];NSString *cur=HFAV032HexBytes((const void*)ra,pd.length);b[@"currentBytes"]=cur;b[@"original"]=cur;b[@"alreadyPatched"]=@([cur caseInsensitiveCompare:next[@"plain"]]==NSOrderedSame);b[@"canonicalEligible"]=@([cur caseInsensitiveCompare:next[@"plain"]]!=NSOrderedSame);}else b[@"canonicalEligible"]=@NO;
        }else{nativeCount++;NSString *rr=r[@"replacementRVA"]?:@"",*ss=r[@"originalSlotRVA"]?:@"";b[@"replacementRVA"]=rr;b[@"originalSlotRVA"]=ss;BOOL rok=NO,sok=NO;uint64_t rv=HFAV032HexValue(rr,&rok),sv=HFAV032HexValue(ss,&sok);uintptr_t repl=rok?l.base+(uintptr_t)rv:0,slot=sok?l.base+(uintptr_t)sv:0;NSDictionary *sem=HFAV032ReplacementSemantics(repl,slot,l);NSString *stype=sem[@"semanticType"]?:@"native-hook";b[@"backendType"]=stype;b[@"receiverStoreRVA"]=sem[@"receiverStoreRVA"]?:@"";b[@"fieldOffsets"]=sem[@"fieldOffsets"]?:@[];b[@"runtimeStateCandidates"]=sem[@"runtimeStateCandidates"]?:@[];if([stype isEqual:@"receiver-capture"])receiverCount++;if([stype isEqual:@"runtime-state"])stateCount++;NSArray *derived=HFAV032FieldConsumers(b[@"fieldOffsets"],image);b[@"derivedPatches"]=derived;derivedCount+=(unsigned)derived.count;b[@"canonicalEligible"]=@NO;}
        [backends addObject:b];HFAV02Log([NSString stringWithFormat:@"[V032-BACKEND] id=%u type=%@ descriptor=%@ target=%@ image=%@ replacement=%@ slot=%@ receiver=%@ derived=%lu",backendId,b[@"backendType"],b[@"descriptorRVA"],b[@"targetRVA"]?:b[@"targetPlain"],b[@"targetImage"]?:@"?",b[@"replacementRVA"]?:@"?",b[@"originalSlotRVA"]?:@"?",b[@"receiverStoreRVA"]?:@"?",(unsigned long)[b[@"derivedPatches"] count]]);
    }
    NSMutableArray *orphans=[NSMutableArray array];for(NSDictionary *r in records)if(HFAV032PatchFamily([r[@"familyValue"] unsignedIntValue])&&![pairedPatch containsObject:r[@"descriptorRVA"]])[orphans addObject:r];NSArray *runtime=HFA5MDispatcherAllEvidence()?:@[];
    NSDictionary *root=@{@"schema":@"com.hfa.runtime-analyzer/v0.3.2",@"mode":@"binary-first-five-class",@"image":[NSString stringWithUTF8String:image],@"decryptRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(decrypt-l.base)],@"summary":@{@"targetDescriptors":@(targets),@"patchDescriptors":@(patches),@"genericSecrets":@(generic),@"backends":@(backends.count),@"staticPatch":@(staticCount),@"nativeHook":@(nativeCount),@"receiverCapture":@(receiverCount),@"runtimeState":@(stateCount),@"derivedPatches":@(derivedCount),@"orphanPatches":@(orphans.count)},@"backends":backends,@"orphanPatchDescriptors":orphans,@"legacyRuntimeEvidence":runtime};NSData *json=[NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:nil];NSString *p32=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_RuntimeAnalyzer_v032.json"];NSString *p03=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_RuntimeAnalyzer_v03.json"];[json writeToFile:p32 atomically:YES];[json writeToFile:p03 atomically:YES];HFAV02Log([NSString stringWithFormat:@"[V032-SCAN-END] image=%s backends=%lu static=%u native=%u receiver=%u state=%u derived=%u orphans=%lu",image,(unsigned long)backends.count,staticCount,nativeCount,receiverCount,stateCount,derivedCount,(unsigned long)orphans.count]);return nativeCount;
}}'''
s = replace_fn(s, 'HFAAnalyzerV02ScanSelectedImage', scan)

s = s.replace('com.hfa.runtime-analyzer/v0.3', 'com.hfa.runtime-analyzer/v0.3.2')
V02.write_text(s)
print('v0.3.2 auto-backend five-class resolver applied')
