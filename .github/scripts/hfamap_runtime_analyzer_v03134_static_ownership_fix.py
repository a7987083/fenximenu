from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
FAMILY=Path('hfamap/src/HFAMapFamilyRuntimeResolver.m')


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
            if depth==0:return start,i+1
    raise SystemExit(f'unterminated function: {signature}')

# 1) Menu discovery must not drop an otherwise valid feature only because its title
#    getter is empty/obfuscated.  The identifier is a stable structural identity and
#    is sufficient as a fallback display label for Class-1 ownership.
f=FAMILY.read_text()
old='''            if (identifier.length && label.length)\n                HFARegisterFeatureDefinition(label.UTF8String, identifier.UTF8String);'''
new='''            if (identifier.length) {\n                NSString *featureLabel = label.length ? label : identifier;\n                HFARegisterFeatureDefinition(featureLabel.UTF8String, identifier.UTF8String);\n                HFAFamilyLog([NSString stringWithFormat:@"[V03134-STATIC-FEATURE] identifier=%@ label=%@ source=%@",\n                              identifier, featureLabel, label.length ? @"menu-label" : @"identifier-fallback"]);\n            }'''
if old not in f: raise SystemExit('family feature-definition anchor missing')
f=f.replace(old,new,1)
FAMILY.write_text(f)

s=TRACE.read_text()

# 2) Remove the v03134 runtime-event ownership injection.  Runtime events are useful
#    diagnostics but cannot be a prerequisite for Class-1 static ownership.
secret_sig='void HFARegisterPatchSecret(id owner, id wrapper, const char *kind)'
a,b=function_span(s,secret_sig)
secret=s[a:b]
event_block='''    if (!d->key[0] && gIdentifier[0] && gWantedKey[0]) {\n        snprintf(d->key, sizeof(d->key), "%s", gWantedKey);\n        HFALog("[V03134-EVENT-OWNERSHIP] event=%u identifier=%s key=%s owner=%p\\n",\n               gEvent, gIdentifier, d->key, owner);\n    }\n'''
if event_block in secret:
    secret=secret.replace(event_block,'',1)
s=s[:a]+secret+s[b:]

# 3) Static ownership policy:
#    A. exact wrapper-secret-RVA -> descriptor key -> feature definition
#    B. if no keyed descriptor exists and the selected menu structurally exposes one
#       and only one feature definition, all canonical static backends belong to that
#       sole feature.  This handles the common one-toggle/multi-patch layout without
#       using button clicks or array ordering.
a,b=function_span(s,'static NSDictionary *HFA03134OwnershipForBackend(NSDictionary *backend)')
owner_fn=r'''static NSDictionary *HFA03134OwnershipForBackend(NSDictionary *backend){
    uint64_t descriptor=HFA03134HexRVA(backend[@"descriptorRVA"]),patchDescriptor=HFA03134HexRVA(backend[@"patchDescriptorRVA"]);if(!descriptor&&!patchDescriptor)return nil;
    NSMutableArray *matches=[NSMutableArray array];
    for(unsigned i=0;i<gDescriptorCount;i++){
        HFADescriptor *d=&gDescriptors[i];if(!d->key[0])continue;NSString *oi=nil,*pi=nil;uint64_t orva=HFA03134WrapperSecretRVA(d->offsetWrapper,&oi),prva=HFA03134WrapperSecretRVA(d->patchWrapper,&pi);unsigned exact=0;
        if(descriptor&&(descriptor==orva||descriptor==prva))exact++;
        if(patchDescriptor&&(patchDescriptor==orva||patchDescriptor==prva))exact++;
        if(!exact)continue;NSDictionary *ident=HFA0312FeatureIdentityForKey(d->key);if(!ident)continue;
        [matches addObject:@{@"descriptorIndex":@(i),@"featureId":ident[@"id"]?:@"",@"title":ident[@"title"]?:ident[@"id"]?:@"",@"key":[NSString stringWithUTF8String:d->key],@"offsetSecretRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)orva],@"patchSecretRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)prva],@"exactFieldMatches":@(exact),@"offsetImage":oi?:@"",@"patchImage":pi?:@"",@"source":@"static-wrapper-secret-rva"}];
    }
    if(matches.count==1){NSDictionary *m=matches.firstObject;HFALog("[V03134-STATIC-OWNERSHIP] backend=%u status=unique source=wrapper-secret-rva feature=%s key=%s descriptorIndex=%u exact=%u\\n",[backend[@"backendId"] unsignedIntValue],[m[@"featureId"] UTF8String]?:"?",[m[@"key"] UTF8String]?:"?",[m[@"descriptorIndex"] unsignedIntValue],[m[@"exactFieldMatches"] unsignedIntValue]);return m;}
    if(matches.count>1){HFALog("[V03134-STATIC-OWNERSHIP] backend=%u status=ambiguous source=wrapper-secret-rva matches=%u descriptor=%s patchDescriptor=%s\\n",[backend[@"backendId"] unsignedIntValue],(unsigned)matches.count,[backend[@"descriptorRVA"] UTF8String]?:"?",[backend[@"patchDescriptorRVA"] UTF8String]?:"?");return nil;}
    if(gFeatureDefinitionCount==1){
        HFAFeatureDefinition *d=&gFeatureDefinitions[0];if(d->identifier[0]){NSString *fid=[NSString stringWithUTF8String:d->identifier];NSString *title=d->label[0]?[NSString stringWithUTF8String:d->label]:fid;NSString *key=d->key[0]?[NSString stringWithUTF8String:d->key]:@"";NSDictionary *m=@{@"descriptorIndex":@(-1),@"featureId":fid?:@"",@"title":title?:fid?:@"",@"key":key?:@"",@"exactFieldMatches":@0,@"source":@"static-singleton-feature-definition"};HFALog("[V03134-STATIC-OWNERSHIP] backend=%u status=unique source=singleton-feature-definition feature=%s descriptor=%s patchDescriptor=%s\\n",[backend[@"backendId"] unsignedIntValue],fid.UTF8String?:"?",[backend[@"descriptorRVA"] UTF8String]?:"?",[backend[@"patchDescriptorRVA"] UTF8String]?:"?");return m;}
    }
    HFALog("[V03134-STATIC-OWNERSHIP] backend=%u status=none featureDefinitions=%u descriptors=%u descriptor=%s patchDescriptor=%s\\n",[backend[@"backendId"] unsignedIntValue],gFeatureDefinitionCount,gDescriptorCount,[backend[@"descriptorRVA"] UTF8String]?:"?",[backend[@"patchDescriptorRVA"] UTF8String]?:"?");return nil;
}'''
s=s[:a]+owner_fn+s[b:]

# 4) Ownership evidence must state the static source; do not claim event ownership.
s=s.replace('e[@"ownershipSource"]=@"wrapper-secret-rva+event-identifier";e[@"ownershipEvidence"]=owner;',
            'e[@"ownershipSource"]=owner[@"source"]?:@"static-structural";e[@"ownershipEvidence"]=owner;',1)
s=s.replace('ownership=secret-rva+event-identifier','ownership=static-structural',1)
TRACE.write_text(s)

out=TRACE.read_text()
if '[V03134-EVENT-OWNERSHIP]' in out: raise SystemExit('runtime event ownership still present')
for req in ['[V03134-STATIC-OWNERSHIP]','static-wrapper-secret-rva','static-singleton-feature-definition','ownership=static-structural']:
    if req not in out: raise SystemExit('static ownership marker missing '+req)
family=FAMILY.read_text()
for req in ['[V03134-STATIC-FEATURE]','identifier-fallback']:
    if req not in family: raise SystemExit('static feature fallback missing '+req)
print('v0.3.13.4 static-first ownership fix applied')
