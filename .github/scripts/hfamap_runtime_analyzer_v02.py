from pathlib import Path

ROOT = Path('hfamap')
PATCH = ROOT/'src/HFAMapPatchExecutionTrace.m'
FAMILY = ROOT/'src/HFAMapFamilyRuntimeResolver.m'
DISPATCH = ROOT/'src/HFAMap5MDispatcherResolver.m'
APPLOCAL = ROOT/'src/HFAMapAppLocalResolver.m'
MAKEFILE = ROOT/'Makefile'
V02 = ROOT/'src/HFAMapRuntimeAnalyzerV02.m'


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
            for j in range(brace, len(text)):
                if text[j] == '{': depth += 1
                elif text[j] == '}':
                    depth -= 1
                    if depth == 0: return start, j + 1
        pos = i + len(needle)


def replace_fn(text, name, replacement):
    a, b = function_span(text, name)
    return text[:a] + replacement + text[b:]

patch = PATCH.read_text()
family = FAMILY.read_text()
dispatch = DISPATCH.read_text()
app = APPLOCAL.read_text()
make = MAKEFILE.read_text()

if 'extern unsigned HFAAnalyzerV02ScanSelectedImage(void);' not in patch:
    patch = patch.replace('extern void HFAProbeKey2Path(uintptr_t getterAddress);',
                          'extern void HFAProbeKey2Path(uintptr_t getterAddress);\nextern unsigned HFAAnalyzerV02ScanSelectedImage(void);')

helper = r'''
static int HFADecryptFingerprintAt(uintptr_t address) {
    if (!address || !HFAReadable(address, 0x44)) return 0;
    uint32_t a=0,b=0,c=0;
    memcpy(&a,(const void *)address,4);
    memcpy(&b,(const void *)(address+0x30),4);
    memcpy(&c,(const void *)(address+0x40),4);
    return a==0xD105C3FFu && b==0xB9400408u && c==0x53187D00u;
}

static uintptr_t HFAResolveDecryptFromGetter(uintptr_t getter, uintptr_t imageBase) {
    uintptr_t fast[] = { getter+0xD00u, getter+0x1204u };
    for (unsigned i=0;i<2;i++) if (HFADecryptFingerprintAt(fast[i])) return fast[i];
    const struct mach_header_64 *h=(const struct mach_header_64 *)imageBase;
    if (!h || h->magic!=MH_MAGIC_64) return 0;
    intptr_t slide=0; uint32_t n=_dyld_image_count();
    for(uint32_t i=0;i<n;i++) if((uintptr_t)_dyld_get_image_header(i)==imageBase){slide=_dyld_get_image_vmaddr_slide(i);break;}
    const uint8_t *cur=(const uint8_t *)(h+1); uintptr_t found=0; unsigned hits=0;
    for(uint32_t i=0;i<h->ncmds;i++){
        const struct load_command *lc=(const struct load_command *)cur; if(!lc->cmdsize) break;
        if(lc->cmd==LC_SEGMENT_64){
            const struct segment_command_64 *seg=(const struct segment_command_64 *)cur;
            const struct section_64 *sec=(const struct section_64 *)(seg+1);
            for(uint32_t s=0;s<seg->nsects;s++) if(!strncmp(sec[s].sectname,"__text",16)){
                uintptr_t start=(uintptr_t)slide+(uintptr_t)sec[s].addr,end=start+(uintptr_t)sec[s].size;
                if(end<=start || end-start>0x3000000u) continue;
                for(uintptr_t p=start;p+0x44<=end;p+=4) if(HFADecryptFingerprintAt(p)){found=p;if(++hits>1)return 0;}
            }
        }
        cur+=lc->cmdsize;
    }
    return hits==1?found:0;
}

static int HFAFeatureLabelNumeric(const char *s) {
    if(!s||!*s) return 0; int digit=0;
    for(const char *p=s;*p;p++){
        if((*p>='0'&&*p<='9')||*p=='.'||*p=='-'||*p=='+'||*p=='%'){if(*p>='0'&&*p<='9')digit=1;continue;}
        if(*p==' '||*p=='x'||*p=='X') continue;
        return 0;
    }
    return digit;
}
'''
anchor='static int HFADecryptWrapper(id wrapper, char *out, size_t outCap, const char *label) {'
if 'HFAResolveDecryptFromGetter' not in patch:
    patch=patch.replace(anchor,helper+'\n'+anchor,1)

new_decrypt=r'''static int HFADecryptWrapper(id wrapper, char *out, size_t outCap, const char *label) {
    if(!wrapper||!out||outCap<2) return 0;
    SEL secretSel=sel_registerName("secret");
    Method getterMethod=class_getInstanceMethod(object_getClass(wrapper),secretSel);
    if(!getterMethod) return 0;
    void *secret=((void *(*)(id,SEL))objc_msgSend)(wrapper,secretSel);
    if(!secret) return 0;
    uint32_t len=0,flags=0; memcpy(&len,secret,4); memcpy(&flags,(uint8_t *)secret+4,4);
    unsigned keyId=flags>>24; size_t blobSize=(size_t)(len&~0xFu)+0x28u;
    if(blobSize<=0x28u) blobSize=0x28u;
    if(!len||len>0x10000u||blobSize>0x11000u||keyId>63u) return 0;
    IMP getter=method_getImplementation(getterMethod); Dl_info gi={0};
    if(!dladdr((void *)getter,&gi)||!gi.dli_fbase) return 0;
    uintptr_t getterRVA=(uintptr_t)getter-(uintptr_t)gi.dli_fbase;
    uintptr_t decryptAddress=HFAResolveDecryptFromGetter((uintptr_t)getter,(uintptr_t)gi.dli_fbase);
    if(!decryptAddress){HFALog("[GENERIC-DECRYPT-SKIP] field=%s image=%s getterRVA=%llX keyId=%u reason=no-unique-fingerprint\n",label,HFABase(gi.dli_fname),(unsigned long long)getterRVA,keyId);return 0;}
    uintptr_t decryptRVA=decryptAddress-(uintptr_t)gi.dli_fbase;
    HFALog("[GENERIC-KEY] field=%s image=%s keyId=%u len=%u flags=%08X getterRVA=%llX decryptRVA=%llX\n",label,HFABase(gi.dli_fname),keyId,len,flags,(unsigned long long)getterRVA,(unsigned long long)decryptRVA);
    const char *image=HFABase(gi.dli_fname);
    if(strcmp(gDetectedTarget,image)!=0){snprintf(gDetectedTarget,sizeof(gDetectedTarget),"%s",image);snprintf(gTarget,sizeof(gTarget),"%s",image);HFALog("[AUTO-TARGET] image=%s getterRVA=%llX decryptRVA=%llX verified=1\n",image,(unsigned long long)getterRVA,(unsigned long long)decryptRVA);}
    void *copy=malloc(blobSize),*plain=calloc(1,(size_t)len+0x20u); if(!copy||!plain){free(copy);free(plain);return 0;} memcpy(copy,secret,blobSize);
    int rc=((HFASecretDecryptFn)decryptAddress)(copy,plain);
    if(rc==0){size_t n=len<outCap-1?len:outCap-1;memcpy(out,plain,n);out[n]=0;} else HFAProbeKey2Path((uintptr_t)getter);
    HFALog("[MAP-DECRYPT] field=%s image=%s getterRVA=%llX decryptRVA=%llX keyId=%u len=%u flags=%08X rc=%d plain=%s\n",label,image,(unsigned long long)getterRVA,(unsigned long long)decryptRVA,keyId,len,flags,rc,rc==0?out:"?");
    free(plain);free(copy);return rc==0;
}'''
patch=replace_fn(patch,'HFADecryptWrapper',new_decrypt)

old='''        snprintf(definition->label, sizeof(definition->label), "%s", label);\n        snprintf(definition->identifier, sizeof(definition->identifier), "%s",\n                 identifier);'''
new='''        if (!definition->label[0] || !HFAFeatureLabelNumeric(label) || HFAFeatureLabelNumeric(definition->label))\n            snprintf(definition->label, sizeof(definition->label), "%s", label);\n        snprintf(definition->identifier, sizeof(definition->identifier), "%s",\n                 identifier);'''
if old in patch: patch=patch.replace(old,new,1)

if '[V02-OWNERSHIP-FINALIZE]' not in patch:
    marker='    HFAWritePatchPackage(exportFeatures, exportTargets);'
    patch=patch.replace(marker,'    unsigned v02Native=HFAAnalyzerV02ScanSelectedImage();\n    HFALog("[V02-OWNERSHIP-FINALIZE] nativeCandidates=%u\\n",v02Native);\n'+marker,1)

if 'HFA5MDispatcherAllEvidence' not in dispatch:
    dispatch += r'''

NSArray *HFA5MDispatcherAllEvidence(void) {
    NSMutableArray *out=[NSMutableArray array];
    NSArray *keys=[[gHFA5MFeatures allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for(NSString *key in keys){NSDictionary *v=HFA5MDispatcherEvidenceForIdentifier(key);if(v)[out addObject:v];}
    return out;
}
'''

retry_anchor='        HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-RESOLVE-END]'
if '[V02-AUTO-RETRY]' not in family and retry_anchor in family:
    family=family.replace(retry_anchor,r'''        if(context.featureControls==0 && context.igmmArrays==0){
            HFAFamilyLog(@"[V02-AUTO-RETRY] reason=no-feature-objects delay=0.30");
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.30]];
            context.seenTargets=[NSMutableSet set];
            for(NSUInteger i=0;i<windowCount;i++){UIWindow *window=windows[i];if(window.rootViewController)HFAFamilyWalkController(&context,window.rootViewController,0);else HFAFamilyWalkView(&context,window,0);}
        }

'''+retry_anchor,1)

needle='if ([standard.lastPathComponent containsString:@"HFAMapUniversal"]) return NO;'
if needle in app:
    app=app.replace(needle,needle+r'''
    NSString *bn=standard.lastPathComponent.lowercaseString;
    if([bn containsString:@"hfamap"]||[bn containsString:@"runtimeanalyzer"]||[bn containsString:@"secretprobe"]||[bn containsString:@"alertdismiss"]) return NO;''',1)

PATCH.write_text(patch);FAMILY.write_text(family);DISPATCH.write_text(dispatch);APPLOCAL.write_text(app)

V02.write_text(r'''#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern const char *HFAAppLocalPrimaryImage(void);
extern unsigned HFAAppLocalCopyClassesForImage(const char *image, Class *buffer, unsigned capacity);
extern NSArray *HFA5MDispatcherAllEvidence(void);
typedef int (*HFASecretDecryptFn)(void *,void *);
typedef struct{uintptr_t start,end;} HFAV02Range;
typedef struct{HFAV02Range text,cfstring;intptr_t slide;uintptr_t base;} HFAV02Layout;

static void HFAV02Log(NSString *line){if(!line.length)return;@synchronized([NSFileHandle class]){NSString *p=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];FILE *f=fopen(p.fileSystemRepresentation,"a");if(!f)return;fprintf(f,"%s\n",line.UTF8String?:"[V02]");fflush(f);fclose(f);}}
static const char *HFAV02Base(const char *p){const char *q=p?strrchr(p,'/'):0;return q?q+1:(p?p:"?");}
static int HFAV02FP(uintptr_t p){uint32_t a=0,b=0,c=0;if(!p)return 0;memcpy(&a,(void*)p,4);memcpy(&b,(void*)(p+0x30),4);memcpy(&c,(void*)(p+0x40),4);return a==0xD105C3FFu&&b==0xB9400408u&&c==0x53187D00u;}
static int64_t HFAV02SX(uint64_t v,unsigned bits){uint64_t s=1ULL<<(bits-1);return(int64_t)((v^s)-s);}
static BOOL HFAV02ADRP(uint32_t w,uintptr_t pc,unsigned *rd,uintptr_t *page){if((w&0x9F000000u)!=0x90000000u)return NO;uint64_t imm=((uint64_t)((w>>5)&0x7FFFFu)<<2)|((w>>29)&3u);if(rd)*rd=w&31u;if(page)*page=(pc&~(uintptr_t)0xFFF)+(HFAV02SX(imm,21)<<12);return YES;}
static BOOL HFAV02ADD(uint32_t w,unsigned *rd,unsigned *rn,uint64_t *imm){if((w&0xFF000000u)!=0x91000000u)return NO;uint64_t x=(w>>10)&0xFFFu;if((w>>22)&1u)x<<=12;if(rd)*rd=w&31u;if(rn)*rn=(w>>5)&31u;if(imm)*imm=x;return YES;}

static BOOL HFAV02LayoutForImage(const char *image,HFAV02Layout *out,NSMutableArray<NSValue*> *ranges){if(!image||!*image||!out)return NO;uint32_t n=_dyld_image_count();for(uint32_t i=0;i<n;i++){const char *p=_dyld_get_image_name(i);if(!p||strcmp(HFAV02Base(p),image))continue;const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header(i);if(!h||h->magic!=MH_MAGIC_64)return NO;HFAV02Layout l={0};l.base=(uintptr_t)h;l.slide=_dyld_get_image_vmaddr_slide(i);const uint8_t *cur=(const uint8_t*)(h+1);for(uint32_t c=0;c<h->ncmds;c++){const struct load_command *lc=(const struct load_command*)cur;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *seg=(const struct segment_command_64*)cur;const struct section_64 *sec=(const struct section_64*)(seg+1);for(uint32_t s=0;s<seg->nsects;s++){uintptr_t a=(uintptr_t)l.slide+(uintptr_t)sec[s].addr,e=a+(uintptr_t)sec[s].size;if(e<=a)continue;if(!strncmp(sec[s].sectname,"__text",16))l.text=(HFAV02Range){a,e};else if(!strncmp(sec[s].sectname,"__cfstring",16))l.cfstring=(HFAV02Range){a,e};if((!strncmp(seg->segname,"__DATA",6)||!strncmp(seg->segname,"__AUTH",6))&&sec[s].size&&sec[s].size<0x2000000u&&strncmp(sec[s].sectname,"__bss",16))[ranges addObject:[NSValue valueWithBytes:&(HFAV02Range){a,e} objCType:@encode(HFAV02Range)]];}}cur+=lc->cmdsize;}*out=l;return l.text.start&&l.text.end>l.text.start;}return NO;}

static uintptr_t HFAV02ResolveDecrypt(const char *image,HFAV02Layout l){Class classes[768]={0};unsigned count=HFAAppLocalCopyClassesForImage(image,classes,768);SEL secret=sel_registerName("secret");for(unsigned i=0;i<count;i++){Method m=class_getInstanceMethod(classes[i],secret);if(!m)continue;uintptr_t getter=(uintptr_t)method_getImplementation(m);Dl_info di={0};if(!dladdr((void*)getter,&di)||strcmp(HFAV02Base(di.dli_fname),image))continue;uintptr_t c[]={getter+0xD00u,getter+0x1204u};for(unsigned k=0;k<2;k++)if(c[k]>=l.text.start&&c[k]+0x44<=l.text.end&&HFAV02FP(c[k]))return c[k];}uintptr_t found=0;unsigned hits=0;for(uintptr_t p=l.text.start;p+0x44<=l.text.end;p+=4)if(HFAV02FP(p)){found=p;if(++hits>1)return 0;}return hits==1?found:0;}
static BOOL HFAV02Printable(const char *s,unsigned len){if(!s||!len)return NO;for(unsigned i=0;i<len;i++){unsigned char c=s[i];if(c==0)break;if(c<0x20||c>0x7E)return NO;}return YES;}
static NSString *HFAV02Kind(NSString *p){if([p hasPrefix:@"0x"]&&p.length>3)return @"target-rva";NSCharacterSet *bad=[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet];if(p.length>=8&&!(p.length&1)&&[p rangeOfCharacterFromSet:bad].location==NSNotFound)return @"patch-hex";return @"string";}

static NSArray *HFAV02Xrefs(uintptr_t target,HFAV02Layout l,uintptr_t *replacement,uintptr_t *slot){NSMutableArray *refs=[NSMutableArray array];if(replacement)*replacement=0;if(slot)*slot=0;const uint32_t *w=(const uint32_t*)l.text.start;NSUInteger n=(l.text.end-l.text.start)/4;for(NSUInteger i=0;i+1<n;i++){unsigned r=0,rd=0,rn=0;uintptr_t pg=0;uint64_t off=0;uintptr_t pc=l.text.start+i*4;if(!HFAV02ADRP(w[i],pc,&r,&pg)||!HFAV02ADD(w[i+1],&rd,&rn,&off)||rd!=r||rn!=r||pg+off!=target)continue;[refs addObject:[NSString stringWithFormat:@"0x%llX",(unsigned long long)(pc-l.base)]];for(NSUInteger j=i+2;j<n&&j<=i+28;j++){unsigned rr=0,rrd=0,rrn=0;uintptr_t p2=0;uint64_t of=0;uintptr_t pc2=l.text.start+j*4;if(!HFAV02ADRP(w[j],pc2,&rr,&p2)||j+1>=n||!HFAV02ADD(w[j+1],&rrd,&rrn,&of)||rrd!=rr||rrn!=rr)continue;uintptr_t value=p2+of;if(rr==3&&value>=l.text.start&&value<l.text.end&&replacement&&!*replacement)*replacement=value;if(rr==4&&!(value>=l.text.start&&value<l.text.end)&&slot&&!*slot)*slot=value;}if(refs.count>=8)break;}return refs;}
static NSArray *HFAV02Hints(uintptr_t function,HFAV02Layout l){if(!function||function<l.text.start||function>=l.text.end)return @[];NSMutableOrderedSet *set=[NSMutableOrderedSet orderedSet];const uint32_t *w=(const uint32_t*)function;NSUInteger n=MIN((NSUInteger)256,(NSUInteger)((l.text.end-function)/4));for(NSUInteger i=0;i+1<n;i++){unsigned r=0,rd=0,rn=0;uintptr_t pg=0;uint64_t off=0;uintptr_t pc=function+i*4;if(!HFAV02ADRP(w[i],pc,&r,&pg)||!HFAV02ADD(w[i+1],&rd,&rn,&off)||r!=rd||r!=rn)continue;uintptr_t a=pg+off;if(a<l.cfstring.start||a+sizeof(uintptr_t)*4>l.cfstring.end)continue;@try{id obj=(id)(void*)a;if([obj isKindOfClass:[NSString class]]){NSString *s=obj;if(s.length&&s.length<96)[set addObject:s];}}@catch(__unused id e){}}return set.array;}

unsigned HFAAnalyzerV02ScanSelectedImage(void){@autoreleasepool{const char *image=HFAAppLocalPrimaryImage();if(!image||!*image){HFAV02Log(@"[V02-SCAN] status=no-selected-image");return 0;}NSMutableArray<NSValue*> *ranges=[NSMutableArray array];HFAV02Layout l={0};if(!HFAV02LayoutForImage(image,&l,ranges)){HFAV02Log(@"[V02-SCAN] status=no-layout");return 0;}uintptr_t decrypt=HFAV02ResolveDecrypt(image,l);if(!decrypt){HFAV02Log([NSString stringWithFormat:@"[V02-SCAN] image=%s status=no-decrypt",image]);return 0;}NSMutableArray *records=[NSMutableArray array];unsigned targets=0,patches=0;for(NSValue *v in ranges){HFAV02Range r={0};[v getValue:&r];for(uintptr_t p=r.start;p+0x30<=r.end;p+=4){uint32_t len=0,flags=0;memcpy(&len,(void*)p,4);memcpy(&flags,(void*)(p+4),4);unsigned keyId=flags>>24,fam=flags&0x00FFFFFFu;if(!len||len>0x200||keyId>63)continue;if(fam!=0x031211u&&fam!=0x021411u&&fam!=0x000101u)continue;size_t blob=(size_t)(len&~0xFu)+0x28u;if(blob<0x28)blob=0x28;if(p+blob>r.end)continue;void *copy=malloc(blob),*plain=calloc(1,len+0x20);if(!copy||!plain){free(copy);free(plain);continue;}memcpy(copy,(void*)p,blob);int rc=((HFASecretDecryptFn)decrypt)(copy,plain);if(rc){HFAV02Log([NSString stringWithFormat:@"[V02-SECRET] image=%s descriptorRVA=0x%llX keyId=%u len=%u flags=%08X rc=%d",image,(unsigned long long)(p-l.base),keyId,len,flags,rc]);free(copy);free(plain);continue;}char buf[0x241]={0};unsigned nc=MIN(len,(uint32_t)0x240);memcpy(buf,plain,nc);free(copy);free(plain);if(!HFAV02Printable(buf,nc))continue;NSString *plainText=[NSString stringWithUTF8String:buf]?:@"";NSString *kind=HFAV02Kind(plainText);if([kind isEqual:@"target-rva"])targets++;else if([kind isEqual:@"patch-hex"])patches++;uintptr_t repl=0,slot=0;NSArray *xrefs=HFAV02Xrefs(p,l,&repl,&slot);NSArray *hints=HFAV02Hints(repl,l);NSMutableDictionary *rec=[@{@"descriptorRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(p-l.base)],@"keyId":@(keyId),@"flags":[NSString stringWithFormat:@"0x%08X",flags],@"kind":kind,@"plain":plainText,@"xrefs":xrefs} mutableCopy];if(repl){rec[@"replacementRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(repl-l.base)];rec[@"featureHints"]=hints?:@[];}if(slot)rec[@"originalSlotRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(slot-l.base)];[records addObject:rec];HFAV02Log([NSString stringWithFormat:@"[V02-DESCRIPTOR] image=%s rva=%@ keyId=%u kind=%@ plain=%@ replacement=%@ originalSlot=%@ hints=%@",image,rec[@"descriptorRVA"],keyId,kind,plainText,rec[@"replacementRVA"]?:@"?",rec[@"originalSlotRVA"]?:@"?",[hints componentsJoinedByString:@","]]);}}unsigned nativeCandidates=targets>patches?targets-patches:0;NSArray *runtime=HFA5MDispatcherAllEvidence()?:@[];NSDictionary *root=@{@"schema":@"com.hfa.runtime-analyzer/v0.2",@"image":[NSString stringWithUTF8String:image],@"decryptRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(decrypt-l.base)],@"descriptors":records,@"targetDescriptors":@(targets),@"patchDescriptors":@(patches),@"nativeTargetCandidates":@(nativeCandidates),@"runtimeFeatures":runtime};NSString *path=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_RuntimeAnalyzer_v02.json"];NSData *json=[NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:nil];[json writeToFile:path atomically:YES];HFAV02Log([NSString stringWithFormat:@"[V02-SCAN-END] image=%s descriptors=%lu targets=%u patches=%u nativeCandidates=%u runtimeFeatures=%lu",image,(unsigned long)records.count,targets,patches,nativeCandidates,(unsigned long)runtime.count]);return nativeCandidates;}}
''')

if 'HFAMapRuntimeAnalyzerV02.m' not in make:
    make=make.replace('src/HFAMapCyberUI.m','src/HFAMapCyberUI.m src/HFAMapRuntimeAnalyzerV02.m')
MAKEFILE.write_text(make)

checks={PATCH:['GENERIC-KEY','V02-OWNERSHIP-FINALIZE','HFAResolveDecryptFromGetter'],FAMILY:['V02-AUTO-RETRY'],DISPATCH:['HFA5MDispatcherAllEvidence'],V02:['com.hfa.runtime-analyzer/v0.2','V02-DESCRIPTOR']}
for p,markers in checks.items():
    s=p.read_text()
    for m in markers:
        if m not in s: raise SystemExit(f'{p}: missing marker {m}')
print('v0.2 runtime analyzer patch applied')
