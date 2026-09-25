from pathlib import Path

SRC = Path('hfamap/src/HFAMapRuntimeAnalyzerV02.m')
text = SRC.read_text()


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
                    if depth == 0:
                        return start, j + 1
        pos = i + len(needle)


def replace_fn(text, name, replacement):
    a, b = function_span(text, name)
    return text[:a] + replacement + text[b:]

replacement = r'''unsigned HFAAnalyzerV02ScanSelectedImage(void){
    static char cachedImage[256] = {0};
    static unsigned cachedNative = 0;
    static BOOL cachedValid = NO;
    @autoreleasepool {
        const char *image=HFAAppLocalPrimaryImage();
        if(!image||!*image){HFAV02Log(@"[V041-SCAN] status=no-selected-image");return 0;}
        if(cachedValid && strcmp(cachedImage,image)==0){
            HFAV02Log([NSString stringWithFormat:@"[V041-SCAN-CACHE-HIT] image=%s nativeCandidates=%u",image,cachedNative]);
            return cachedNative;
        }

        NSMutableArray<NSValue*> *ranges=[NSMutableArray array];
        HFAV02Layout l={0};
        if(!HFAV02LayoutForImage(image,&l,ranges)){HFAV02Log(@"[V041-SCAN] status=no-layout");return 0;}
        uintptr_t decrypt=HFAV02ResolveDecrypt(image,l);
        if(!decrypt){HFAV02Log([NSString stringWithFormat:@"[V041-SCAN] image=%s status=no-decrypt",image]);return 0;}

        NSMutableArray *records=[NSMutableArray array];
        unsigned targets=0,patches=0,nativeCandidates=0,skippedGeneric=0;
        for(NSValue *v in ranges){
            HFAV02Range r={0}; [v getValue:&r];
            for(uintptr_t p=r.start;p+0x30<=r.end;p+=4){
                uint32_t len=0,flags=0; memcpy(&len,(void*)p,4); memcpy(&flags,(void*)(p+4),4);
                unsigned keyId=flags>>24,fam=flags&0x00FFFFFFu;
                if(!len||len>0x200||keyId>63)continue;
                if(fam==0x000101u){skippedGeneric++;continue;}
                if(fam!=0x031211u&&fam!=0x021411u)continue;
                size_t blob=(size_t)(len&~0xFu)+0x28u; if(blob<0x28)blob=0x28;
                if(p+blob>r.end)continue;
                void *copy=malloc(blob),*plain=calloc(1,len+0x20);
                if(!copy||!plain){free(copy);free(plain);continue;}
                memcpy(copy,(void*)p,blob);
                int rc=((HFASecretDecryptFn)decrypt)(copy,plain);
                if(rc){
                    HFAV02Log([NSString stringWithFormat:@"[V041-SECRET] image=%s descriptorRVA=0x%llX keyId=%u len=%u flags=%08X rc=%d",image,(unsigned long long)(p-l.base),keyId,len,flags,rc]);
                    free(copy);free(plain);continue;
                }
                char buf[0x241]={0}; unsigned nc=MIN(len,(uint32_t)0x240); memcpy(buf,plain,nc);
                free(copy);free(plain);
                if(!HFAV02Printable(buf,nc))continue;
                NSString *plainText=[NSString stringWithUTF8String:buf]?:@"";
                NSString *kind=HFAV02Kind(fam,plainText);
                BOOL isTarget=[kind isEqual:@"target-rva"];
                BOOL isPatch=[kind isEqual:@"patch-data"];
                if(!isTarget&&!isPatch)continue;
                if(isTarget)targets++; else patches++;

                uintptr_t repl=0,slot=0;
                NSArray *xrefs=@[];
                NSArray *hints=@[];
                if(isTarget){
                    xrefs=HFAV02Xrefs(p,l,&repl,&slot);
                    if(repl)hints=HFAV02Hints(repl,l);
                }
                BOOL nativeEvidence=isTarget&&(repl||slot);
                if(nativeEvidence)nativeCandidates++;
                NSMutableDictionary *rec=[@{
                    @"descriptorRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(p-l.base)],
                    @"keyId":@(keyId),
                    @"flags":[NSString stringWithFormat:@"0x%08X",flags],
                    @"kind":kind,
                    @"plain":plainText,
                    @"xrefs":xrefs
                } mutableCopy];
                if(repl){rec[@"replacementRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(repl-l.base)];rec[@"featureHints"]=hints?:@[];}
                if(slot)rec[@"originalSlotRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(slot-l.base)];
                if(nativeEvidence)rec[@"sink"]=@"native-hook";
                else if(isPatch)rec[@"sink"]=@"patch-data";
                else rec[@"sink"]=@"target-unpaired";
                [records addObject:rec];
                HFAV02Log([NSString stringWithFormat:@"[V041-DESCRIPTOR] image=%s rva=%@ keyId=%u kind=%@ plain=%@ replacement=%@ originalSlot=%@ hints=%@",image,rec[@"descriptorRVA"],keyId,kind,plainText,rec[@"replacementRVA"]?:@"?",rec[@"originalSlotRVA"]?:@"?",[hints componentsJoinedByString:@","]]);
            }
        }

        NSArray *runtime=HFA5MDispatcherAllEvidence()?:@[];
        NSDictionary *root=@{
            @"schema":@"com.hfa.runtime-analyzer/v0.3",
            @"image":[NSString stringWithUTF8String:image],
            @"decryptRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(decrypt-l.base)],
            @"descriptors":records,
            @"targetDescriptors":@(targets),
            @"patchDescriptors":@(patches),
            @"nativeTargetCandidates":@(nativeCandidates),
            @"runtimeFeatures":runtime,
            @"stabilityProfile":@"v0.4.1-bounded"
        };
        NSString *path=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_RuntimeAnalyzer_v03.json"];
        NSData *json=[NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:nil];
        [json writeToFile:path atomically:YES];
        snprintf(cachedImage,sizeof(cachedImage),"%s",image);
        cachedNative=nativeCandidates;
        cachedValid=YES;
        HFAV02Log([NSString stringWithFormat:@"[V041-SCAN-END] image=%s descriptors=%lu targets=%u patches=%u nativeCandidates=%u runtimeFeatures=%lu skippedGeneric=%u",image,(unsigned long)records.count,targets,patches,nativeCandidates,(unsigned long)runtime.count,skippedGeneric]);
        return nativeCandidates;
    }
}'''

text = replace_fn(text, 'HFAAnalyzerV02ScanSelectedImage', replacement)
SRC.write_text(text)
print('v0.4.1 stability scanner applied')
