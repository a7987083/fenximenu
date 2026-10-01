#import "HFAMapRuntimeTargetDecrypt.h"
#import "HFARuntimeSemanticAnalyzer.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// v0.3.13.19: read-only runtime target decrypt probe.
// It never installs hooks and never writes the target/menu image. Encrypted
// records are copied to scratch memory before the menu's own decrypt routine is
// invoked. A plaintext target is promoted only when it maps uniquely to an
// executable image range.

typedef int (*HFARTDDecryptFn)(void *, void *);

typedef struct {
    uint32_t imageIndex;
    const struct mach_header_64 *header;
    intptr_t slide;
    const char *path;
    char basename[192];
    char uuid[40];
    uint64_t preferredTextStart;
    uint64_t preferredTextEnd;
    uintptr_t runtimeTextStart;
    uintptr_t runtimeTextEnd;
} HFARTDImage;

typedef struct {
    uintptr_t runtime;
    uint64_t preferredRVA;
    uint32_t length;
    uint32_t flags;
    uint32_t family;
    uint8_t keyId;
    size_t blobSize;
    BOOL target;
} HFARTDRecord;

static const uint32_t kHFARTDTargetA=0x031201u;
static const uint32_t kHFARTDTargetB=0x031211u;
static const uint32_t kHFARTDPatchA =0x021401u;
static const uint32_t kHFARTDPatchB =0x021411u;
static const char *kHFARTDVersion="0.3.13.19-runtime-target-decrypt";

static const char *HFARTDBase(const char *path){
    if(!path)return "?";const char *p=strrchr(path,'/');return p?p+1:path;
}

static void HFARTDUUID(const struct mach_header_64 *h,char out[40]){
    if(!h||h->magic!=MH_MAGIC_64){snprintf(out,40,"?");return;}
    const uint8_t *c=(const uint8_t *)(h+1);
    for(uint32_t i=0;i<h->ncmds;i++){
        const struct load_command *lc=(const struct load_command *)c;
        if(lc->cmdsize<sizeof(*lc))break;
        if(lc->cmd==LC_UUID&&lc->cmdsize>=sizeof(struct uuid_command)){
            const struct uuid_command *u=(const struct uuid_command *)c;const uint8_t *b=u->uuid;
            snprintf(out,40,"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                     b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);return;
        }
        c+=lc->cmdsize;
    }
    snprintf(out,40,"?");
}

static BOOL HFARTDAppLocalPath(const char *path){
    if(!path||!*path)return NO;
    NSString *p=[NSString stringWithUTF8String:path];NSString *bundle=[[NSBundle mainBundle] bundlePath];
    if(!p||!bundle.length)return NO;
    return [p hasPrefix:bundle];
}

static BOOL HFARTDReadable(uintptr_t address,size_t size){
    if(!address||!size||address+size<address)return NO;
    mach_vm_address_t r=(mach_vm_address_t)address;mach_vm_size_t rs=0;vm_region_basic_info_data_64_t info={0};
    mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t object=MACH_PORT_NULL;
    if(mach_vm_region(mach_task_self(),&r,&rs,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&object)!=KERN_SUCCESS)return NO;
    return (info.protection&VM_PROT_READ)&&r<=address&&address+size<=r+(uintptr_t)rs;
}

static NSString *HFARTDHex(const uint8_t *b,size_t n){
    NSMutableString *s=[NSMutableString stringWithCapacity:n*2];for(size_t i=0;i<n;i++)[s appendFormat:@"%02X",b[i]];return s;
}

static NSString *HFARTDLogPath(void){
    NSString *bid=[[NSBundle mainBundle] bundleIdentifier]?:@"unknown";
    return [NSHomeDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"Documents/HFARTD_%@_RuntimeTargetDecrypt.jsonl",bid]];
}

static void HFARTDEmit(NSDictionary *record){
    if(!record)return;NSMutableDictionary *m=[NSMutableDictionary dictionaryWithDictionary:record];
    m[@"probeVersion"]=[NSString stringWithUTF8String:kHFARTDVersion];
    NSData *j=[NSJSONSerialization dataWithJSONObject:m options:0 error:nil];if(!j)return;
    NSMutableData *line=[NSMutableData dataWithData:j];const uint8_t nl='\n';[line appendBytes:&nl length:1];
    NSString *p=HFARTDLogPath();NSFileManager *fm=[NSFileManager defaultManager];if(![fm fileExistsAtPath:p])[fm createFileAtPath:p contents:nil attributes:nil];
    NSFileHandle *h=[NSFileHandle fileHandleForWritingAtPath:p];if(!h)return;@try{[h seekToEndOfFile];[h writeData:line];[h synchronizeFile];[h closeFile];}@catch(NSException *e){(void)e;}
}

static int64_t HFARTDSX(uint64_t v,unsigned bits){uint64_t m=UINT64_C(1)<<(bits-1);return (int64_t)((v^m)-m);}
static BOOL HFARTDADR(uint32_t w,uintptr_t pc,unsigned *rd,uintptr_t *value){
    if((w&0x9F000000u)!=0x10000000u)return NO;uint64_t imm=(((uint64_t)((w>>5)&0x7FFFFu))<<2)|((w>>29)&3u);
    if(rd)*rd=w&31u;if(value)*value=(uintptr_t)((int64_t)pc+HFARTDSX(imm,21));return YES;
}
static BOOL HFARTDADRP(uint32_t w,uintptr_t pc,unsigned *rd,uintptr_t *value){
    if((w&0x9F000000u)!=0x90000000u)return NO;uint64_t imm=(((uint64_t)((w>>5)&0x7FFFFu))<<2)|((w>>29)&3u);
    if(rd)*rd=w&31u;if(value)*value=(uintptr_t)((int64_t)(pc&~(uintptr_t)0xFFF)+(HFARTDSX(imm,21)<<12));return YES;
}
static BOOL HFARTDAddImm(uint32_t w,unsigned *rd,unsigned *rn,uint64_t *imm){
    if((w&0xFF000000u)!=0x91000000u)return NO;uint64_t v=(w>>10)&0xFFFu;if((w>>22)&1u)v<<=12;
    if(rd)*rd=w&31u;if(rn)*rn=(w>>5)&31u;if(imm)*imm=v;return YES;
}

static BOOL HFARTDLoadImage(uint32_t index,HFARTDImage *out){
    if(!out||index>=_dyld_image_count())return NO;const struct mach_header_64 *h=(const struct mach_header_64 *)_dyld_get_image_header(index);const char *path=_dyld_get_image_name(index);
    if(!h||h->magic!=MH_MAGIC_64||!path)return NO;HFARTDImage x={0};x.imageIndex=index;x.header=h;x.slide=_dyld_get_image_vmaddr_slide(index);x.path=path;snprintf(x.basename,sizeof(x.basename),"%s",HFARTDBase(path));HFARTDUUID(h,x.uuid);
    const uint8_t *c=(const uint8_t *)(h+1);for(uint32_t i=0;i<h->ncmds;i++){
        const struct load_command *lc=(const struct load_command *)c;if(lc->cmdsize<sizeof(*lc))break;
        if(lc->cmd==LC_SEGMENT_64&&lc->cmdsize>=sizeof(struct segment_command_64)){
            const struct segment_command_64 *g=(const struct segment_command_64 *)c;
            if(g->initprot&VM_PROT_EXECUTE){uint64_t ps=g->vmaddr,pe=g->vmaddr+g->vmsize;uintptr_t rs=(uintptr_t)((intptr_t)g->vmaddr+x.slide),re=rs+(uintptr_t)g->vmsize;
                if(!x.preferredTextStart||ps<x.preferredTextStart)x.preferredTextStart=ps;if(pe>x.preferredTextEnd)x.preferredTextEnd=pe;
                if(!x.runtimeTextStart||rs<x.runtimeTextStart)x.runtimeTextStart=rs;if(re>x.runtimeTextEnd)x.runtimeTextEnd=re;}
        }
        c+=lc->cmdsize;
    }
    *out=x;return x.runtimeTextStart&&x.runtimeTextEnd>x.runtimeTextStart;
}

static NSUInteger HFARTDFindDecrypt(const HFARTDImage *image,uintptr_t matches[4]){
    if(!image||!image->header)return 0;NSUInteger n=0;const uint8_t *c=(const uint8_t *)(image->header+1);
    for(uint32_t i=0;i<image->header->ncmds;i++){
        const struct load_command *lc=(const struct load_command *)c;if(lc->cmdsize<sizeof(*lc))break;
        if(lc->cmd==LC_SEGMENT_64&&lc->cmdsize>=sizeof(struct segment_command_64)){
            const struct segment_command_64 *g=(const struct segment_command_64 *)c;const struct section_64 *s=(const struct section_64 *)(g+1);
            for(uint32_t j=0;j<g->nsects;j++,s++)if(!strncmp(s->segname,"__TEXT",16)&&!strncmp(s->sectname,"__text",16)&&s->size>=0x44){
                uintptr_t start=(uintptr_t)((intptr_t)s->addr+image->slide),end=start+(uintptr_t)s->size;if(!HFARTDReadable(start,(size_t)MIN((uint64_t)s->size,UINT64_C(0x1000))))continue;
                for(uintptr_t p=start;p+0x44<=end;p+=4){uint32_t a=0,b=0,d=0;memcpy(&a,(void *)p,4);if(a!=0xD105C3FFu)continue;memcpy(&b,(void *)(p+0x30),4);memcpy(&d,(void *)(p+0x40),4);if(b==0xB9400408u&&d==0x53187D00u){if(n<4)matches[n]=p;n++;}}
            }
        }
        c+=lc->cmdsize;
    }
    return n;
}

static BOOL HFARTDRecordFamily(uint32_t flags,BOOL *target){uint32_t f=flags&0xFFFFFFu;if(f==kHFARTDTargetA||f==kHFARTDTargetB){if(target)*target=YES;return YES;}if(f==kHFARTDPatchA||f==kHFARTDPatchB){if(target)*target=NO;return YES;}return NO;}

static NSUInteger HFARTDScanRecords(const HFARTDImage *image,HFARTDRecord *out,NSUInteger cap){
    if(!image||!out||!cap)return 0;NSUInteger count=0;const uint8_t *c=(const uint8_t *)(image->header+1);
    for(uint32_t i=0;i<image->header->ncmds&&count<cap;i++){
        const struct load_command *lc=(const struct load_command *)c;if(lc->cmdsize<sizeof(*lc))break;
        if(lc->cmd==LC_SEGMENT_64&&lc->cmdsize>=sizeof(struct segment_command_64)){
            const struct segment_command_64 *g=(const struct segment_command_64 *)c;if(!(g->initprot&VM_PROT_READ)){c+=lc->cmdsize;continue;}
            const struct section_64 *s=(const struct section_64 *)(g+1);for(uint32_t j=0;j<g->nsects&&count<cap;j++,s++){
                uint32_t st=s->flags&SECTION_TYPE;if(!s->size||st==S_ZEROFILL||st==S_GB_ZEROFILL||st==S_THREAD_LOCAL_ZEROFILL)continue;
                uintptr_t start=(uintptr_t)((intptr_t)s->addr+image->slide),end=start+(uintptr_t)s->size;if(end<start||!HFARTDReadable(start,(size_t)MIN((uint64_t)s->size,UINT64_C(8))))continue;
                for(uintptr_t p=start;p+8<=end&&count<cap;p+=8){uint32_t len=0,flags=0;memcpy(&len,(void *)p,4);memcpy(&flags,(void *)(p+4),4);BOOL isTarget=NO;if(!HFARTDRecordFamily(flags,&isTarget)||len==0||len>0x100u)continue;
                    size_t blob=(size_t)(len&~0xFu)+0x28u;if(blob<0x28u||p+blob>end)continue;
                    HFARTDRecord r={0};r.runtime=p;r.preferredRVA=(uint64_t)((intptr_t)p-image->slide);r.length=len;r.flags=flags;r.family=flags&0xFFFFFFu;r.keyId=(uint8_t)(flags>>24);r.blobSize=blob;r.target=isTarget;out[count++]=r;}
            }
        }
        c+=lc->cmdsize;
    }
    return count;
}

static const HFARTDRecord *HFARTDRecordAt(const HFARTDRecord *r,NSUInteger n,uint64_t preferred){for(NSUInteger i=0;i<n;i++)if(r[i].preferredRVA==preferred)return &r[i];return NULL;}

static NSUInteger HFARTDXrefs(const HFARTDImage *image,uintptr_t target,uintptr_t *xrefPC,NSUInteger cap){
    if(!image||!xrefPC||!cap)return 0;NSUInteger n=0;const uint8_t *c=(const uint8_t *)(image->header+1);
    for(uint32_t ci=0;ci<image->header->ncmds;ci++){
        const struct load_command *lc=(const struct load_command *)c;if(lc->cmdsize<sizeof(*lc))break;
        if(lc->cmd==LC_SEGMENT_64&&lc->cmdsize>=sizeof(struct segment_command_64)){
            const struct segment_command_64 *g=(const struct segment_command_64 *)c;const struct section_64 *s=(const struct section_64 *)(g+1);
            for(uint32_t j=0;j<g->nsects;j++,s++)if(!strncmp(s->segname,"__TEXT",16)&&!strncmp(s->sectname,"__text",16)){
                uintptr_t start=(uintptr_t)((intptr_t)s->addr+image->slide),end=start+(uintptr_t)s->size;
                for(uintptr_t pc=start;pc+4<=end;pc+=4){uint32_t w=0;memcpy(&w,(void *)pc,4);unsigned rd=0;uintptr_t v=0;
                    if(HFARTDADR(w,pc,&rd,&v)&&v==target){if(n<cap)xrefPC[n]=pc;n++;continue;}
                    if(HFARTDADRP(w,pc,&rd,&v)){for(unsigned k=1;k<=4&&pc+4u*k+4<=end;k++){uint32_t w2=0;memcpy(&w2,(void *)(pc+4u*k),4);unsigned d=0,rn=0;uint64_t imm=0;if(HFARTDAddImm(w2,&d,&rn,&imm)&&d==rd&&rn==rd){if(v+imm==target){if(n<cap)xrefPC[n]=pc;n++;}break;}}}
                }
            }
        }
        c+=lc->cmdsize;
    }
    return n;
}

static void HFARTDRegsNear(uintptr_t start,uintptr_t textEnd,uintptr_t values[32],BOOL known[32]){
    uintptr_t pending[32]={0};BOOL havePending[32]={0};memset(known,0,sizeof(BOOL)*32);
    for(unsigned i=0;i<14&&start+4u*i+4<=textEnd;i++){uintptr_t pc=start+4u*i;uint32_t w=0;memcpy(&w,(void *)pc,4);unsigned rd=0,rn=0;uintptr_t v=0;uint64_t imm=0;
        if(HFARTDADR(w,pc,&rd,&v)){values[rd]=v;known[rd]=YES;continue;}if(HFARTDADRP(w,pc,&rd,&v)){pending[rd]=v;havePending[rd]=YES;continue;}
        if(HFARTDAddImm(w,&rd,&rn,&imm)&&havePending[rn]){values[rd]=pending[rn]+imm;known[rd]=YES;}
    }
}

static BOOL HFARTDWithinExec(const HFARTDImage *i,uintptr_t p){return i&&p>=i->runtimeTextStart&&p<i->runtimeTextEnd;}
static BOOL HFARTDWithinImageSegment(const HFARTDImage *image,uintptr_t p,vm_prot_t wanted){
    if(!image||!p)return NO;const uint8_t *c=(const uint8_t *)(image->header+1);for(uint32_t n=0;n<image->header->ncmds;n++){const struct load_command *lc=(const struct load_command *)c;if(lc->cmdsize<sizeof(*lc))break;if(lc->cmd==LC_SEGMENT_64&&lc->cmdsize>=sizeof(struct segment_command_64)){const struct segment_command_64 *g=(const struct segment_command_64 *)c;uintptr_t a=(uintptr_t)((intptr_t)g->vmaddr+image->slide),e=a+(uintptr_t)g->vmsize;if((g->initprot&wanted)==wanted&&p>=a&&p<e)return YES;}c+=lc->cmdsize;}return NO;
}

static NSString *HFARTDPlainString(const uint8_t *plain,uint32_t len){
    if(!plain||!len)return nil;size_t n=0;while(n<len&&plain[n])n++;if(!n)n=len;for(size_t i=0;i<n;i++)if(plain[i]<0x20||plain[i]>0x7E)return nil;return [[[NSString alloc]initWithBytes:plain length:n encoding:NSUTF8StringEncoding] autorelease];
}

static BOOL HFARTDParseHexTarget(NSString *s,uint64_t *out){
    if(!s.length||!out)return NO;NSString *x=[s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];if([x hasPrefix:@"0x"]||[x hasPrefix:@"0X"])x=[x substringFromIndex:2];if(!x.length||x.length>16)return NO;
    NSCharacterSet *bad=[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet];if([x rangeOfCharacterFromSet:bad].location!=NSNotFound)return NO;
    unsigned long long v=0;NSScanner *sc=[NSScanner scannerWithString:x];if(![sc scanHexLongLong:&v]||![sc isAtEnd])return NO;*out=(uint64_t)v;return YES;
}

static NSArray *HFARTDTargetCandidates(uint64_t preferred,uintptr_t *uniqueRuntime,NSString **resolution){
    NSMutableArray *primary=[NSMutableArray array],*secondary=[NSMutableArray array];uint32_t count=_dyld_image_count();
    for(uint32_t idx=0;idx<count;idx++){HFARTDImage im={0};if(!HFARTDLoadImage(idx,&im))continue;BOOL hit=NO;const uint8_t *c=(const uint8_t *)(im.header+1);for(uint32_t n=0;n<im.header->ncmds;n++){const struct load_command *lc=(const struct load_command *)c;if(lc->cmdsize<sizeof(*lc))break;if(lc->cmd==LC_SEGMENT_64&&lc->cmdsize>=sizeof(struct segment_command_64)){const struct segment_command_64 *g=(const struct segment_command_64 *)c;if((g->initprot&VM_PROT_EXECUTE)&&preferred>=g->vmaddr&&preferred<g->vmaddr+g->vmsize){hit=YES;break;}}c+=lc->cmdsize;}if(!hit)continue;
        NSDictionary *d=@{@"image":[NSString stringWithUTF8String:im.basename],@"path":[NSString stringWithUTF8String:im.path],@"uuid":[NSString stringWithUTF8String:im.uuid],@"preferredTargetRVA":[NSString stringWithFormat:@"0x%llX",preferred],@"runtimeAddress":[NSString stringWithFormat:@"0x%llX",(unsigned long long)((intptr_t)preferred+im.slide)]};
        if(im.header->filetype==MH_EXECUTE||!strcmp(im.basename,"UnityFramework"))[primary addObject:d];else if(HFARTDAppLocalPath(im.path))[secondary addObject:d];
    }
    NSArray *chosen=primary.count?primary:secondary;if(chosen.count==1){NSDictionary *d=chosen[0];if(uniqueRuntime)*uniqueRuntime=(uintptr_t)strtoull([[d objectForKey:@"runtimeAddress"] UTF8String]+2,NULL,16);if(resolution)*resolution=primary.count?@"unique-main-or-unity-exec-range":@"unique-app-local-exec-range";}else{if(uniqueRuntime)*uniqueRuntime=0;if(resolution)*resolution=chosen.count?@"ambiguous-exec-range":@"no-exec-range";}
    return chosen;
}

void HFARuntimeTargetDecryptScan(void){
    @autoreleasepool{
        CFAbsoluteTime begun=CFAbsoluteTimeGetCurrent();const CFTimeInterval budget=0.80;uint32_t imageCount=_dyld_image_count();unsigned eligible=0,decrypted=0,resolved=0;
        HFARTDEmit(@{@"record":@"runtime-target-decrypt-begin",@"loadedImages":@(imageCount),@"analysisOnly":@YES,@"memoryWritten":@NO});
        for(uint32_t idx=0;idx<imageCount;idx++){
            if(CFAbsoluteTimeGetCurrent()-begun>budget){HFARTDEmit(@{@"record":@"runtime-target-decrypt-budget",@"budgetMs":@800,@"action":@"fail-soft",@"analysisOnly":@YES});break;}
            HFARTDImage image={0};if(!HFARTDLoadImage(idx,&image)||!HFARTDAppLocalPath(image.path))continue;if(strstr(image.basename,"HFAMap")||strstr(image.basename,"HFARuntimeAnalyzer"))continue;
            uintptr_t dec[4]={0};NSUInteger decCount=HFARTDFindDecrypt(&image,dec);if(decCount!=1)continue;eligible++;
            HFARTDRecord records[160]={0};NSUInteger recordCount=HFARTDScanRecords(&image,records,160);if(!recordCount)continue;
            HFARTDEmit(@{@"record":@"runtime-target-image",@"image":[NSString stringWithUTF8String:image.basename],@"uuid":[NSString stringWithUTF8String:image.uuid],@"decryptRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)((intptr_t)dec[0]-image.slide)],@"decryptFingerprintUnique":@YES,@"recordCount":@(recordCount),@"analysisOnly":@YES});
            for(NSUInteger ri=0;ri<recordCount;ri++){
                HFARTDRecord *r=&records[ri];if(!r->target)continue;const HFARTDRecord *next=HFARTDRecordAt(records,recordCount,r->preferredRVA+r->blobSize);if(next&&!next->target)continue; // existing static patch backend
                uintptr_t xrefs[4]={0};NSUInteger xrefCount=HFARTDXrefs(&image,r->runtime,xrefs,4);uintptr_t vals[32]={0};BOOL known[32]={0};uintptr_t replacement=0,slot=0;
                if(xrefCount==1){HFARTDRegsNear(xrefs[0],image.runtimeTextEnd,vals,known);if(known[3]&&HFARTDWithinExec(&image,vals[3]))replacement=vals[3];if(known[4]&&HFARTDWithinImageSegment(&image,vals[4],VM_PROT_WRITE))slot=vals[4];}
                void *copy=malloc(r->blobSize);uint8_t *plain=calloc(1,(size_t)r->length+0x20u);int rc=-999;if(copy&&plain){memcpy(copy,(void *)r->runtime,r->blobSize);rc=((HFARTDDecryptFn)dec[0])(copy,plain);}NSString *ps=(rc==0)?HFARTDPlainString(plain,r->length):nil;uint64_t targetPreferred=0;BOOL targetParsed=ps?HFARTDParseHexTarget(ps,&targetPreferred):NO;
                NSMutableDictionary *out=[NSMutableDictionary dictionary];out[@"record"]=@"runtime-target-backend";out[@"image"]=[NSString stringWithUTF8String:image.basename];out[@"uuid"]=[NSString stringWithUTF8String:image.uuid];out[@"targetRecordRVA"]=[NSString stringWithFormat:@"0x%llX",r->preferredRVA];out[@"targetFlags"]=[NSString stringWithFormat:@"0x%08X",r->flags];out[@"keyId"]=@(r->keyId);out[@"decryptRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)((intptr_t)dec[0]-image.slide)];out[@"decryptRC"]=@(rc);out[@"xrefCount"]=@(xrefCount);out[@"analysisOnly"]=@YES;out[@"memoryWritten"]=@NO;out[@"scratchCopyDecrypt"]=@YES;
                if(xrefCount==1)out[@"installerXrefRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)((intptr_t)xrefs[0]-image.slide)];if(replacement)out[@"replacementRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)((intptr_t)replacement-image.slide)];if(slot)out[@"originalSlotRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)((intptr_t)slot-image.slide)];if(replacement&&slot)out[@"replacementSemantic"]=HFASemanticAnalyzeReplacement(replacement,slot)?:@{};
                if(rc==0){decrypted++;out[@"plainHex"]=HFARTDHex(plain,r->length);if(ps)out[@"plain"]=ps;out[@"targetParsedAsHex"]=@(targetParsed);if(targetParsed){out[@"gameTargetRVA"]=[NSString stringWithFormat:@"0x%llX",targetPreferred];uintptr_t live=0;NSString *why=nil;NSArray *candidates=HFARTDTargetCandidates(targetPreferred,&live,&why);out[@"targetResolution"]=why?:@"";out[@"targetCandidates"]=candidates?:@[];if(live&&candidates.count==1){resolved++;out[@"liveGameTargetAddress"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)live];if(HFARTDReadable(live,16))out[@"targetEntryBytes"]=HFARTDHex((const uint8_t *)live,16);NSDictionary *method=HFAIL2CPPDescribeOwningMethod(live);if(method.count)out[@"il2cppOwner"]=method;out[@"confidence"]=@"runtime-decrypted-unique-exec-range";}else out[@"confidence"]=@"runtime-decrypted-target-unresolved-image";}}
                else out[@"confidence"]=@"decrypt-failed-or-key-not-ready";
                HFARTDEmit(out);free(plain);free(copy);
            }
        }
        HFARTDEmit(@{@"record":@"runtime-target-decrypt-end",@"eligibleImages":@(eligible),@"decryptedNativeRecords":@(decrypted),@"resolvedGameTargets":@(resolved),@"elapsedMs":@((CFAbsoluteTimeGetCurrent()-begun)*1000.0),@"analysisOnly":@YES,@"memoryWritten":@NO});
    }
}