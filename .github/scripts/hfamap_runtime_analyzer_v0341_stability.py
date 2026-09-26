from pathlib import Path
import re

ROOT = Path('hfamap')
SRC = ROOT / 'src' / 'HFAMapRuntimeAnalyzerV02.m'
SEM = ROOT / 'src' / 'HFARuntimeSemanticAnalyzer.m'
HDR = ROOT / 'src' / 'HFARuntimeSemanticAnalyzer.h'
UI = ROOT / 'src' / 'HFAMapCyberUI.m'


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


# ---------------------------------------------------------------------------
# 1) Semantic module hardening: bounded snapshot, budgets, stage log, safe ptr
# ---------------------------------------------------------------------------
sem = SEM.read_text()
imports = '#import "HFAMapOutputPaths.h"\n#include <dispatch/dispatch.h>\n#include <fcntl.h>\n#include <pthread.h>\n#include <unistd.h>\n'
if '#import "HFAMapOutputPaths.h"' not in sem:
    sem = sem.replace('#import "HFARuntimeSemanticAnalyzer.h"\n', '#import "HFARuntimeSemanticAnalyzer.h"\n' + imports, 1)

helper_anchor = '// This module intentionally fails closed.'
if 'HFASemanticResetWholeScanBudget' not in sem:
    helpers = r'''
static uint64_t gHFASemScanId = 0;
static CFAbsoluteTime gHFASemWholeDeadline = 0;

void HFASemanticResetWholeScanBudget(void) {
    gHFASemScanId++;
    gHFASemWholeDeadline = CFAbsoluteTimeGetCurrent() + 4.0;
}

static BOOL HFASemanticWholeBudgetAvailable(void) {
    return gHFASemWholeDeadline <= 0 || CFAbsoluteTimeGetCurrent() <= gHFASemWholeDeadline;
}

static void HFASemStageLog(NSString *phase, NSString *detail) {
    @autoreleasepool {
        NSString *path = HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v0341_stage.log");
        const char *fs = path.fileSystemRepresentation;
        if (!fs) return;
        uint64_t tid = (uint64_t)pthread_mach_thread_np(pthread_self());
        NSString *line = [NSString stringWithFormat:@"[%@] scan=%llu thread=%llu %@\n",
                          phase ?: @"V0341-STAGE",
                          (unsigned long long)gHFASemScanId,
                          (unsigned long long)tid,
                          detail ?: @""];
        NSData *d = [line dataUsingEncoding:NSUTF8StringEncoding];
        if (!d.length) return;
        int fd = open(fs, O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (fd < 0) return;
        (void)write(fd, d.bytes, d.length);
        close(fd);
    }
}

static BOOL HFASemReadPointer(uintptr_t address, uintptr_t *value) {
    if (!address || !value) return NO;
    uintptr_t tmp = 0;
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address,
                                         (vm_size_t)sizeof(tmp),
                                         (vm_address_t)&tmp,
                                         &got);
    if (kr != KERN_SUCCESS || got != (vm_size_t)sizeof(tmp)) return NO;
    *value = tmp;
    return YES;
}

'''
    sem = sem.replace(helper_anchor, helpers + helper_anchor, 1)

# Replace only the body-local live instruction pointer with an immutable snapshot.
a, b = function_span(sem, 'HFASemanticAnalyzeReplacement')
fn = sem[a:b]
old = '    if (!HFASemImageForAddress(replacement,&image)) return @{@"status":@"image-unavailable",@"semanticType":@"unknown-runtime"};\n    NSUInteger count=MIN((NSUInteger)256,(NSUInteger)((image.textEnd-replacement)/4));\n    const uint32_t *words=(const uint32_t *)replacement;'
new = r'''    if (!HFASemanticWholeBudgetAvailable()) {
        HFASemStageLog(@"V0341-SEM-SKIP", @"reason=whole-scan-budget");
        return @{@"status":@"whole-scan-budget-exceeded",@"semanticType":@"unknown-runtime"};
    }
    if (!HFASemImageForAddress(replacement,&image)) {
        HFASemStageLog(@"V0341-SEM-SKIP", @"reason=image-unavailable");
        return @{@"status":@"image-unavailable",@"semanticType":@"unknown-runtime"};
    }
    NSUInteger count=MIN((NSUInteger)256,(NSUInteger)((image.textEnd-replacement)/4));
    uint32_t snapshot[256]={0};
    vm_size_t got=0;
    size_t want=count*sizeof(uint32_t);
    HFASemStageLog(@"V0341-SNAPSHOT-BEGIN", [NSString stringWithFormat:@"replacement=0x%llX bytes=%lu",(unsigned long long)replacement,(unsigned long)want]);
    kern_return_t snapKR=vm_read_overwrite(mach_task_self(),(vm_address_t)replacement,(vm_size_t)want,(vm_address_t)snapshot,&got);
    if(snapKR!=KERN_SUCCESS||got<sizeof(uint32_t)){
        HFASemStageLog(@"V0341-SNAPSHOT-FAIL", [NSString stringWithFormat:@"kr=%d got=%lu",snapKR,(unsigned long)got]);
        return @{@"status":@"snapshot-failed",@"semanticType":@"unknown-runtime",@"kernReturn":@(snapKR),@"bytesRead":@(got)};
    }
    count=MIN(count,(NSUInteger)(got/sizeof(uint32_t)));
    const uint32_t *words=snapshot;
    CFAbsoluteTime semStarted=CFAbsoluteTimeGetCurrent();
    BOOL budgetExceeded=NO;
    HFASemStageLog(@"V0341-SNAPSHOT-END", [NSString stringWithFormat:@"instructions=%lu",(unsigned long)count]);'''
if old not in fn:
    raise SystemExit('v0341 semantic snapshot anchor missing')
fn = fn.replace(old, new, 1)

loop_old = '    for(NSUInteger i=0;i<count;i++){\n        uintptr_t pc=replacement+i*4;uint32_t w=words[i];'
loop_new = r'''    for(NSUInteger i=0;i<count;i++){
        if((i&15u)==0u && (CFAbsoluteTimeGetCurrent()-semStarted)>0.25){budgetExceeded=YES;break;}
        uintptr_t pc=replacement+i*4;uint32_t w=words[i];'''
if loop_old not in fn:
    raise SystemExit('v0341 per-backend budget anchor missing')
fn = fn.replace(loop_old, loop_new, 1)

unsafe = 'else if(eff&&HFASemReadable(eff,sizeof(uintptr_t))){uintptr_t p=0;memcpy(&p,(void*)eff,sizeof(p));addr[rd]=p;addrKnown[rd]=p!=0;}'
safe = 'else if(eff){uintptr_t p=0;if(HFASemReadPointer(eff,&p)){addr[rd]=p;addrKnown[rd]=p!=0;}else addrKnown[rd]=NO;}'
if unsafe not in fn:
    raise SystemExit('v0341 unsafe pointer-read anchor missing')
fn = fn.replace(unsafe, safe, 1)

ret_old = '    return @{\n        @"status":@"ok",\n'
ret_new = r'''    CFAbsoluteTime semElapsed=(CFAbsoluteTimeGetCurrent()-semStarted)*1000.0;
    HFASemStageLog(@"V0341-SEM-END", [NSString stringWithFormat:@"type=%@ budget=%@ elapsedMs=%.2f",semantic,budgetExceeded?@"exceeded":@"ok",semElapsed]);
    return @{
        @"status":budgetExceeded?@"budget-exceeded":@"ok",
        @"elapsedMs":@(semElapsed),
        @"budgetExceeded":@(budgetExceeded),
'''
if ret_old not in fn:
    raise SystemExit('v0341 semantic return anchor missing')
fn = fn.replace(ret_old, ret_new, 1)
sem = sem[:a] + fn + sem[b:]

# ---------------------------------------------------------------------------
# 2) Cached, thread-attached IL2CPP enrichment wrapper. Default use is OFF.
# ---------------------------------------------------------------------------
if 'HFAIL2CPPDescribeOwningMethodCached' not in sem:
    sem += r'''

NSDictionary<NSString *, id> *HFAIL2CPPDescribeOwningMethodCached(uintptr_t target) {
    if (!target) return @{@"status":@"no-target"};
    static NSMutableDictionary<NSNumber *, NSDictionary *> *cache;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ cache=[NSMutableDictionary dictionary]; });
    NSNumber *key=@(target);
    @synchronized(cache){ NSDictionary *hit=cache[key]; if(hit){HFASemStageLog(@"V0341-IL2CPP-CACHE-HIT",[NSString stringWithFormat:@"target=0x%llX",(unsigned long long)target]);return hit;} }
    HFASemStageLog(@"V0341-IL2CPP-CACHE-MISS",[NSString stringWithFormat:@"target=0x%llX",(unsigned long long)target]);

    typedef void *(*DomainGetFn)(void);
    typedef void *(*ThreadAttachFn)(void *);
    typedef void (*ThreadDetachFn)(void *);
    DomainGetFn domainGet=(DomainGetFn)dlsym(RTLD_DEFAULT,"il2cpp_domain_get");
    ThreadAttachFn threadAttach=(ThreadAttachFn)dlsym(RTLD_DEFAULT,"il2cpp_thread_attach");
    ThreadDetachFn threadDetach=(ThreadDetachFn)dlsym(RTLD_DEFAULT,"il2cpp_thread_detach");
    void *attached=NULL;
    if(domainGet&&threadAttach){void *domain=domainGet();if(domain)attached=threadAttach(domain);}
    NSDictionary *result=nil;
    @try { result=HFAIL2CPPDescribeOwningMethod(target); }
    @catch(NSException *e) { result=@{@"status":@"objc-exception",@"name":e.name?:@"",@"reason":e.reason?:@""}; }
    if(attached&&threadDetach)threadDetach(attached);
    if(!result)result=@{@"status":@"no-result"};
    @synchronized(cache){cache[key]=result;}
    return result;
}
'''

SEM.write_text(sem)

hdr = HDR.read_text()
if 'HFASemanticResetWholeScanBudget' not in hdr:
    hdr = hdr.replace('FOUNDATION_EXPORT NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacement(', 'FOUNDATION_EXPORT void HFASemanticResetWholeScanBudget(void);\n\nFOUNDATION_EXPORT NSDictionary<NSString *, id> *HFASemanticAnalyzeReplacement(', 1)
if 'HFAIL2CPPDescribeOwningMethodCached' not in hdr:
    hdr = hdr.replace('FOUNDATION_EXPORT NSDictionary<NSString *, id> *HFAIL2CPPDescribeOwningMethod(\n    uintptr_t targetRuntimeAddress);', 'FOUNDATION_EXPORT NSDictionary<NSString *, id> *HFAIL2CPPDescribeOwningMethod(\n    uintptr_t targetRuntimeAddress);\n\nFOUNDATION_EXPORT NSDictionary<NSString *, id> *HFAIL2CPPDescribeOwningMethodCached(\n    uintptr_t targetRuntimeAddress);', 1)
HDR.write_text(hdr)

# ---------------------------------------------------------------------------
# 3) Main analyzer integration: static backends skip semantic; IL2CPP opt-in.
# ---------------------------------------------------------------------------
s = SRC.read_text()
needle = '''NSDictionary *sem34=HFASemanticAnalyzeReplacement(repl,slot);NSString *stype34=[sem34[@"semanticType"] isKindOfClass:NSString.class]?sem34[@"semanticType"]:@"unknown-runtime";
        b[@"semanticEvidence"]=sem34;b[@"legacySemanticType"]=stype;
        if(![stype34 isEqual:@"unknown-runtime"]){b[@"semanticType"]=stype34;b[@"backendType"]=@"runtime-semantic";}else b[@"semanticType"]=stype;
        uintptr_t targetRuntime=(uintptr_t)[target[@"runtimeAddress"] unsignedLongLongValue];NSDictionary *own34=HFAIL2CPPDescribeOwningMethod(targetRuntime);b[@"owningMethod"]=own34?:@{};'''
replacement = r'''BOOL semanticEligible=(repl!=0)&&![stype isEqual:@"static-patch"];
        NSDictionary *sem34=nil;
        HFAV02Log([NSString stringWithFormat:@"[V0341-SEM-BEGIN] id=%u eligible=%@ type=%@ replacement=%@",backendId,semanticEligible?@"yes":@"no",stype,b[@"replacementRVA"]?:@"?"]);
        if(semanticEligible){
            @try{sem34=HFASemanticAnalyzeReplacement(repl,slot);}
            @catch(NSException *e){sem34=@{@"status":@"objc-exception",@"semanticType":@"unknown-runtime",@"name":e.name?:@"",@"reason":e.reason?:@""};}
        }else sem34=@{@"status":@"skipped-static-or-no-replacement",@"semanticType":stype?:@"unknown-runtime"};
        NSString *stype34=[sem34[@"semanticType"] isKindOfClass:NSString.class]?sem34[@"semanticType"]:@"unknown-runtime";
        b[@"semanticEvidence"]=sem34;b[@"legacySemanticType"]=stype;
        if(semanticEligible&&![stype34 isEqual:@"unknown-runtime"]){b[@"semanticType"]=stype34;b[@"backendType"]=@"runtime-semantic";}else b[@"semanticType"]=stype;
        HFAV02Log([NSString stringWithFormat:@"[V0341-SEM-END] id=%u status=%@ semantic=%@",backendId,sem34[@"status"]?:@"?",stype34]);
        uintptr_t targetRuntime=(uintptr_t)[target[@"runtimeAddress"] unsignedLongLongValue];
        BOOL enrichEnabled=[[NSUserDefaults standardUserDefaults] boolForKey:@"HFAEnableIL2CPPEnrichmentV0341"];
        NSDictionary *own34=nil;
        if(enrichEnabled&&targetRuntime){HFAV02Log([NSString stringWithFormat:@"[V0341-IL2CPP-BEGIN] id=%u target=0x%llX",backendId,(unsigned long long)targetRuntime]);@try{own34=HFAIL2CPPDescribeOwningMethodCached(targetRuntime);}@catch(NSException *e){own34=@{@"status":@"objc-exception",@"name":e.name?:@"",@"reason":e.reason?:@""};}HFAV02Log([NSString stringWithFormat:@"[V0341-IL2CPP-END] id=%u status=%@",backendId,own34[@"status"]?:@"?"]);}else own34=@{@"status":@"disabled-by-default",@"optInKey":@"HFAEnableIL2CPPEnrichmentV0341"};
        b[@"owningMethod"]=own34?:@{};'''
if needle not in s:
    raise SystemExit('v0341 main integration anchor missing')
s = s.replace(needle, replacement, 1)

scan_anchor = 'unsigned HFAAnalyzerV02ScanSelectedImage(void){@autoreleasepool{'
if scan_anchor not in s:
    raise SystemExit('v0341 scan entry anchor missing')
s = s.replace(scan_anchor, scan_anchor + '\n    HFASemanticResetWholeScanBudget();HFAV02Log(@"[V0341-SCAN-BEGIN] semanticBudgetSec=4.0 perBackendMs=250 enrichment=default-off");', 1)

s = s.replace('com.hfa.runtime-analyzer/v0.3.4', 'com.hfa.runtime-analyzer/v0.3.4.1', 1)
s = s.replace('[V034-BACKEND]', '[V0341-BACKEND]').replace('[V034-SCAN-END]', '[V0341-SCAN-END]').replace('[V034-DECRYPT]', '[V0341-DECRYPT]')
out_old = 'NSString *p34=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v034.json");'
out_new = 'NSString *p341=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v0341.json");NSString *p34=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v034.json");'
if out_old not in s:
    raise SystemExit('v0341 output anchor missing')
s = s.replace(out_old, out_new, 1)
write_old = '[json writeToFile:p34 atomically:YES];[json writeToFile:p33 atomically:YES];'
write_new = '[json writeToFile:p341 atomically:YES];[json writeToFile:p34 atomically:YES];[json writeToFile:p33 atomically:YES];'
if write_old not in s:
    raise SystemExit('v0341 output write anchor missing')
s = s.replace(write_old, write_new, 1)
SRC.write_text(s)

# ---------------------------------------------------------------------------
# 4) Dedicated serial AutoBackend queue (it was already background; harden it).
# ---------------------------------------------------------------------------
ui = UI.read_text()
if 'HFAV0341AnalyzerQueue' not in ui:
    helper = r'''
static dispatch_queue_t HFAV0341AnalyzerQueue(void) {
    static dispatch_queue_t q;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ q=dispatch_queue_create("com.hfa.runtime-analyzer.v0341", DISPATCH_QUEUE_SERIAL); });
    return q;
}

'''
    impl = ui.find('@implementation')
    if impl < 0:
        raise SystemExit('v0341 CyberUI @implementation missing')
    ui = ui[:impl] + helper + ui[impl:]
if 'dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0)' not in ui:
    raise SystemExit('v0341 background queue anchor missing')
ui = ui.replace('dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0)', 'HFAV0341AnalyzerQueue()', 1)
ui = ui.replace('HFAMap RuntimeAnalyzer v0.3.4 SemanticBackend', 'HFAMap RuntimeAnalyzer v0.3.4.1 Stability', 2)
UI.write_text(ui)

# ---------------------------------------------------------------------------
# 5) Low-cost boot breadcrumbs in existing log strings for Rogue early crash.
# ---------------------------------------------------------------------------
for path in list((ROOT/'src').glob('*.m')) + list((ROOT/'src').glob('*.mm')):
    text = path.read_text()
    before = text
    text = text.replace('[HFALearn UI v1.8.7 KeyRegisterProbe] loaded\\n', '[HFALearn UI v1.8.7 KeyRegisterProbe] loaded\\n[V0341-BOOT-01] legacy-log-ready\\n')
    text = text.replace('[HFAMap v1.9.37 CleanFamilyResolver] loaded\\n', '[HFAMap v1.9.37 CleanFamilyResolver] loaded\\n[V0341-BOOT-02] family-resolver-ready\\n')
    text = text.replace('[HFALearn v1.9.29 JailpatchRuntimeProfiler] loaded\\n', '[HFALearn v1.9.29 JailpatchRuntimeProfiler] loaded\\n[V0341-BOOT-03] runtime-profiler-ready\\n')
    if text != before:
        path.write_text(text)

# ---------------------------------------------------------------------------
# Hard gates.
# ---------------------------------------------------------------------------
sem = SEM.read_text(); s = SRC.read_text(); ui = UI.read_text(); hdr = HDR.read_text()
required_sem = ['HFASemanticResetWholeScanBudget','HFAMap_RuntimeAnalyzer_v0341_stage.log','vm_read_overwrite','snapshot[256]','budgetExceeded','HFAIL2CPPDescribeOwningMethodCached','il2cpp_thread_attach','V0341-IL2CPP-CACHE-HIT']
for x in required_sem:
    if x not in sem: raise SystemExit('v0341 semantic hardening missing: '+x)
required_src = ['[V0341-SCAN-BEGIN]','[V0341-SEM-BEGIN]','[V0341-SEM-END]','disabled-by-default','HFAEnableIL2CPPEnrichmentV0341','HFAMap_RuntimeAnalyzer_v0341.json','com.hfa.runtime-analyzer/v0.3.4.1']
for x in required_src:
    if x not in s: raise SystemExit('v0341 main integration missing: '+x)
if 'HFAV0341AnalyzerQueue()' not in ui or 'dispatch_queue_create("com.hfa.runtime-analyzer.v0341", DISPATCH_QUEUE_SERIAL)' not in ui:
    raise SystemExit('v0341 dedicated serial queue missing')
if 'HFAIL2CPPDescribeOwningMethodCached' not in hdr:
    raise SystemExit('v0341 cached enrichment header missing')
print('v0.3.4.1 semantic stability patch applied')
