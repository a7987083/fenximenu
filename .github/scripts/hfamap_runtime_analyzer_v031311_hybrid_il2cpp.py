from pathlib import Path

GENERIC=Path('hfamap/src/HFAMapGenericMenuResolver.m')
EXPORTER=Path('hfamap/src/HFAMapJSONExport.m')
MAKEFILE=Path('hfamap/Makefile')
UI=Path('hfamap/src/HFAMapCyberUI.m')

g=GENERIC.read_text()
if '#import "HFAMapIL2CPPRuntimeResolver.h"' not in g:
    g=g.replace('#import <Foundation/Foundation.h>','#import <Foundation/Foundation.h>\n#import "HFAMapIL2CPPRuntimeResolver.h"',1)
old='''static NSDictionary *HFAAddressInfo(const void *address) {
    if (!address) return nil;
    Dl_info info = {0};
    if (!dladdr(address, &info) || !info.dli_fbase || !info.dli_fname) return nil;
    uintptr_t value = (uintptr_t)address;
    uintptr_t base = (uintptr_t)info.dli_fbase;
    return @{
        @"image": [NSString stringWithUTF8String:HFABaseName(info.dli_fname)] ?: @"?",
        @"rva": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(value - base)]
    };
}'''
new='''static NSDictionary *HFAAddressInfo(const void *address) {
    if (!address) return nil;
    Dl_info info = {0};
    if (!dladdr(address, &info) || !info.dli_fbase || !info.dli_fname) return nil;
    uintptr_t value = (uintptr_t)address;
    uintptr_t base = (uintptr_t)info.dli_fbase;
    NSMutableDictionary *out=[NSMutableDictionary dictionaryWithObjectsAndKeys:
        [NSString stringWithUTF8String:HFABaseName(info.dli_fname)] ?: @"?", @"image",
        [NSString stringWithFormat:@"0x%llX", (unsigned long long)(value - base)], @"rva", nil];
    NSDictionary *il2cpp=HFAIL2CPPResolveNativeAddress(address);
    if([il2cpp isKindOfClass:[NSDictionary class]]&&il2cpp.count){
        [out setObject:il2cpp forKey:@"il2cpp"];
        HFAGenericLog("[V031311-HYBRID] image=%s rva=%s il2cpp=%s\\n",
                      [[out objectForKey:@"image"] UTF8String]?:"?",
                      [[out objectForKey:@"rva"] UTF8String]?:"?",
                      [[il2cpp objectForKey:@"canonical"] UTF8String]?:"?");
    }
    return out;
}'''
if old not in g: raise SystemExit('HFAAddressInfo anchor missing')
g=g.replace(old,new,1)
GENERIC.write_text(g)

x=EXPORTER.read_text()
if '#import "HFAMapIL2CPPRuntimeResolver.h"' not in x:
    x=x.replace('#import <Foundation/Foundation.h>','#import <Foundation/Foundation.h>\n#import "HFAMapIL2CPPRuntimeResolver.h"',1)
needle='''        if (targetIdentities.count) root[@"targetIdentities"] = targetIdentities;
        if (haveIdentity) root[@"identityFile"] = identityName;'''
replacement='''        if (targetIdentities.count) root[@"targetIdentities"] = targetIdentities;
        root[@"il2cppRuntime"] = HFAIL2CPPResolverStatus();
        if (haveIdentity) root[@"identityFile"] = identityName;'''
if needle not in x: raise SystemExit('exporter root anchor missing')
x=x.replace(needle,replacement,1)
EXPORTER.write_text(x)

m=MAKEFILE.read_text()
needle='src/HFAMapGenericMenuResolver.m'
if 'src/HFAMapIL2CPPRuntimeResolver.m' not in m:
    if needle not in m: raise SystemExit('Makefile anchor missing')
    m=m.replace(needle,'src/HFAMapIL2CPPRuntimeResolver.m '+needle,1)
MAKEFILE.write_text(m)

u=UI.read_text()
u=u.replace('HFAMap RuntimeAnalyzer v0.3.13.10 ObjectReturnTaintResolver','HFAMap RuntimeAnalyzer v0.3.13.11 HybridIL2CPPRuntimeResolver')
UI.write_text(u)
print('v0.3.13.11 hybrid IL2CPP integration applied')
