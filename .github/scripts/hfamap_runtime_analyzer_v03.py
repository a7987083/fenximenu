from pathlib import Path

ROOT = Path('hfamap')
V02 = ROOT / 'src/HFAMapRuntimeAnalyzerV02.m'
FAMILY = ROOT / 'src/HFAMapFamilyRuntimeResolver.m'
PATCH = ROOT / 'src/HFAMapPatchExecutionTrace.m'


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
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return start, j + 1
        pos = i + len(needle)


def replace_fn(text, name, replacement):
    a, b = function_span(text, name)
    return text[:a] + replacement + text[b:]


v = V02.read_text()
family = FAMILY.read_text()
patch = PATCH.read_text()

new_layout = r'''static BOOL HFAV02LayoutForImage(const char *image,HFAV02Layout *out,NSMutableArray<NSValue*> *ranges){
    if(!image||!*image||!out)return NO;
    uint32_t n=_dyld_image_count();
    for(uint32_t i=0;i<n;i++){
        const char *p=_dyld_get_image_name(i);
        if(!p||strcmp(HFAV02Base(p),image))continue;
        const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header(i);
        if(!h||h->magic!=MH_MAGIC_64)return NO;
        HFAV02Layout l={0};
        l.base=(uintptr_t)h;
        l.slide=_dyld_image_vmaddr_slide(i);
        const uint8_t *cur=(const uint8_t*)(h+1);
        for(uint32_t c=0;c<h->ncmds;c++){
            const struct load_command *lc=(const struct load_command*)cur;
            if(!lc->cmdsize)break;
            if(lc->cmd==LC_SEGMENT_64){
                const struct segment_command_64 *seg=(const struct segment_command_64*)cur;
                const struct section_64 *sec=(const struct section_64*)(seg+1);
                for(uint32_t s=0;s<seg->nsects;s++){
                    uintptr_t a=(uintptr_t)l.slide+(uintptr_t)sec[s].addr;
                    uintptr_t e=a+(uintptr_t)sec[s].size;
                    if(e<=a)continue;
                    if(!strncmp(sec[s].sectname,"__text",16))l.text=(HFAV02Range){a,e};
                    else if(!strncmp(sec[s].sectname,"__cfstring",16))l.cfstring=(HFAV02Range){a,e};

                    BOOL dataFamily=(!strncmp(seg->segname,"__DATA",6)||!strncmp(seg->segname,"__AUTH",6));
                    BOOL textConst=(!strncmp(seg->segname,"__TEXT",16)&&!strncmp(sec[s].sectname,"__const",16));
                    BOOL zeroFill=(!strncmp(sec[s].sectname,"__bss",16)||!strncmp(sec[s].sectname,"__common",16));
                    if((dataFamily||textConst)&&!zeroFill&&sec[s].size&&sec[s].size<0x2000000u){
                        HFAV02Range rr={a,e};
                        [ranges addObject:[NSValue valueWithBytes:&rr objCType:@encode(HFAV02Range)]];
                    }
                }
            }
            cur+=lc->cmdsize;
        }
        *out=l;
        return l.text.start&&l.text.end>l.text.start;
    }
    return NO;
}'''
v = replace_fn(v, 'HFAV02LayoutForImage', new_layout)

if 'HFAV03ADR(' not in v:
    anchor = 'static BOOL HFAV02ADRP('
    idx = v.find(anchor)
    if idx < 0:
        raise SystemExit('HFAV02ADRP anchor missing')
    helper = r'''static BOOL HFAV03ADR(uint32_t w,uintptr_t pc,unsigned *rd,uintptr_t *addr){
    if((w&0x9F000000u)!=0x10000000u)return NO;
    uint64_t imm=((uint64_t)((w>>5)&0x7FFFFu)<<2)|((w>>29)&3u);
    int64_t off=HFAV02SX(imm,21);
    if(rd)*rd=w&31u;
    if(addr)*addr=(uintptr_t)((int64_t)pc+off);
    return YES;
}

static BOOL HFAV03Materialize(const uint32_t *w,NSUInteger n,NSUInteger i,uintptr_t pc,
                              unsigned *reg,uintptr_t *value,NSUInteger *used){
    unsigned r=0,rd=0,rn=0; uintptr_t a=0,page=0; uint64_t off=0;
    if(HFAV03ADR(w[i],pc,&r,&a)){
        if(reg)*reg=r;if(value)*value=a;if(used)*used=1;return YES;
    }
    if(HFAV02ADRP(w[i],pc,&r,&page)&&i+1<n&&HFAV02ADD(w[i+1],&rd,&rn,&off)&&rd==r&&rn==r){
        if(reg)*reg=r;if(value)*value=page+off;if(used)*used=2;return YES;
    }
    return NO;
}

'''
    v = v[:idx] + helper + v[idx:]

new_xrefs = r'''static NSArray *HFAV02Xrefs(uintptr_t target,HFAV02Layout l,uintptr_t *replacement,uintptr_t *slot){
    NSMutableArray *refs=[NSMutableArray array];
    if(replacement)*replacement=0;
    if(slot)*slot=0;
    const uint32_t *w=(const uint32_t*)l.text.start;
    NSUInteger n=(l.text.end-l.text.start)/4;
    for(NSUInteger i=0;i<n;i++){
        unsigned reg=0; uintptr_t value=0; NSUInteger used=0;
        uintptr_t pc=l.text.start+i*4;
        if(!HFAV03Materialize(w,n,i,pc,&reg,&value,&used)||value!=target)continue;
        [refs addObject:[NSString stringWithFormat:@"0x%llX",(unsigned long long)(pc-l.base)]];
        if(reg!=2){ if(refs.count>=12)break; continue; }

        for(NSUInteger j=i+used;j<n&&j<=i+40;j++){
            unsigned rr=0; uintptr_t vv=0; NSUInteger uu=0;
            uintptr_t pc2=l.text.start+j*4;
            if(!HFAV03Materialize(w,n,j,pc2,&rr,&vv,&uu))continue;
            if(rr==3&&vv>=l.text.start&&vv<l.text.end&&replacement&&!*replacement)
                *replacement=vv;
            if(rr==4&&!(vv>=l.text.start&&vv<l.text.end)&&slot&&!*slot)
                *slot=vv;
            if(replacement&&slot&&*replacement&&*slot)break;
        }
        if(refs.count>=12)break;
    }
    return refs;
}'''
v = replace_fn(v, 'HFAV02Xrefs', new_xrefs)

new_kind = r'''static NSString *HFAV02Kind(uint32_t fam,NSString *p){
    if(fam==0x031211u)return @"target-rva";
    if(fam==0x021411u)return @"patch-data";
    if(fam==0x000101u)return @"generic-string";
    if([p hasPrefix:@"0x"]&&p.length>3)return @"string-rva-like";
    return @"unknown";
}'''
v = replace_fn(v, 'HFAV02Kind', new_kind)
v = v.replace('HFAV02Kind(plainText)', 'HFAV02Kind(fam,plainText)')

v = v.replace('unsigned targets=0,patches=0;', 'unsigned targets=0,patches=0,nativeCandidates=0;')
old_count = 'if([kind isEqual:@"target-rva"])targets++;else if([kind isEqual:@"patch-hex"])patches++;'
new_count = 'if([kind isEqual:@"target-rva"])targets++;else if([kind isEqual:@"patch-data"])patches++;'
if old_count not in v:
    raise SystemExit('descriptor count anchor missing')
v = v.replace(old_count, new_count, 1)

old_xrefs = 'uintptr_t repl=0,slot=0;NSArray *xrefs=HFAV02Xrefs(p,l,&repl,&slot);NSArray *hints=HFAV02Hints(repl,l);'
new_xrefs_line = '''uintptr_t repl=0,slot=0;NSArray *xrefs=HFAV02Xrefs(p,l,&repl,&slot);NSArray *hints=HFAV02Hints(repl,l);
        BOOL nativeEvidence=[kind isEqual:@"target-rva"]&&(repl||slot);
        if(nativeEvidence)nativeCandidates++;'''
if old_xrefs not in v:
    raise SystemExit('xrefs anchor missing')
v = v.replace(old_xrefs, new_xrefs_line, 1)

old_rec = 'if(repl){rec[@"replacementRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(repl-l.base)];rec[@"featureHints"]=hints?:@[];}if(slot)rec[@"originalSlotRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(slot-l.base)];'
new_rec = '''if(repl){rec[@"replacementRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(repl-l.base)];rec[@"featureHints"]=hints?:@[];}
        if(slot)rec[@"originalSlotRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(slot-l.base)];
        if(nativeEvidence)rec[@"sink"]=@"native-hook";
        else if([kind isEqual:@"patch-data"])rec[@"sink"]=@"patch-data";
        else if([kind isEqual:@"target-rva"])rec[@"sink"]=@"target-unpaired";'''
if old_rec not in v:
    raise SystemExit('record anchor missing')
v = v.replace(old_rec, new_rec, 1)

v = v.replace('unsigned nativeCandidates=targets>patches?targets-patches:0;', '')
v = v.replace('[V02-DESCRIPTOR]', '[V03-DESCRIPTOR]')
v = v.replace('[V02-SECRET]', '[V03-SECRET]')
v = v.replace('[V02-SCAN-END]', '[V03-SCAN-END]')
v = v.replace('[V02-SCAN]', '[V03-SCAN]')
v = v.replace('com.hfa.runtime-analyzer/v0.2', 'com.hfa.runtime-analyzer/v0.3')
v = v.replace('HFAMap_RuntimeAnalyzer_v02.json', 'HFAMap_RuntimeAnalyzer_v03.json')

proto = 'extern void HFA5MDispatcherObserveAction(id sender, id target, SEL action);\n'
if proto.strip() not in family:
    anchor = 'extern void HFAGenericMenuObserveAction(id sender, id target, SEL action);\n'
    if anchor not in family:
        raise SystemExit('family extern anchor missing')
    family = family.replace(anchor, anchor + proto, 1)
call_anchor = '            HFAGenericMenuObserveAction(control, target, action);\n            context->actions++;'
call_new = '''            HFAGenericMenuObserveAction(control, target, action);
            if (strcmp(context->family, "runtime-5m") == 0)
                HFA5MDispatcherObserveAction(control, target, action);
            context->actions++;'''
if call_anchor not in family:
    raise SystemExit('family action anchor missing')
family = family.replace(call_anchor, call_new, 1)
family = family.replace('[V02-AUTO-RETRY]', '[V03-AUTO-RETRY]')

new_register = r'''void HFARegisterFeatureDefinition(const char *label, const char *identifier) {
    if (!identifier || !*identifier) return;
    const char *chosen = label;
    if (!chosen || !*chosen || strcmp(chosen, "?") == 0 || HFAFeatureLabelNumeric(chosen))
        chosen = identifier;

    char key[128] = {0};
    size_t identifierLength = strlen(identifier);
    if (identifierLength > 7 &&
        strcmp(identifier + identifierLength - 7, "-switch") == 0)
        snprintf(key, sizeof(key), "%s", identifier);
    else
        snprintf(key, sizeof(key), "%s-switch", identifier);

    for (unsigned i = 0; i < gFeatureDefinitionCount; i++) {
        HFAFeatureDefinition *definition = &gFeatureDefinitions[i];
        if (strcmp(definition->key, key) != 0) continue;

        int oldWeak = !definition->label[0] || strcmp(definition->label, "?") == 0 ||
                      HFAFeatureLabelNumeric(definition->label);
        int newStrong = chosen && *chosen && strcmp(chosen, "?") != 0 &&
                        !HFAFeatureLabelNumeric(chosen);
        if (oldWeak || newStrong)
            snprintf(definition->label, sizeof(definition->label), "%s", chosen);
        snprintf(definition->identifier, sizeof(definition->identifier), "%s", identifier);
        return;
    }

    if (gFeatureDefinitionCount >= 128) return;
    HFAFeatureDefinition *definition = &gFeatureDefinitions[gFeatureDefinitionCount++];
    memset(definition, 0, sizeof(*definition));
    snprintf(definition->label, sizeof(definition->label), "%s", chosen);
    snprintf(definition->identifier, sizeof(definition->identifier), "%s", identifier);
    snprintf(definition->key, sizeof(definition->key), "%s", key);
}'''
patch = replace_fn(patch, 'HFARegisterFeatureDefinition', new_register)
patch = patch.replace('[V02-OWNERSHIP-FINALIZE]', '[V03-OWNERSHIP-FINALIZE]')
patch = patch.replace('v02Native', 'v03Native')

V02.write_text(v)
FAMILY.write_text(family)
PATCH.write_text(patch)
print('v0.3 ownership resolver patch applied')
