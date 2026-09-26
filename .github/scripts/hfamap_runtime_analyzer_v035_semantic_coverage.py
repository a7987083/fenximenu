from pathlib import Path

ROOT=Path('hfamap')
SEM=ROOT/'src'/'HFARuntimeSemanticAnalyzer.m'
HDR=ROOT/'src'/'HFARuntimeSemanticAnalyzer.h'


def function_span(text,name):
    i=text.find(name+'(')
    if i<0: raise SystemExit(name+' missing')
    start=text.rfind('\n',0,i)+1
    b=text.find('{',i); depth=0; instr=False; esc=False
    for j in range(b,len(text)):
        ch=text[j]
        if instr:
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch=='"': instr=False
            continue
        if ch=='"': instr=True; continue
        if ch=='{': depth+=1
        elif ch=='}':
            depth-=1
            if depth==0:return start,j+1
    raise SystemExit(name+' unterminated')

s=SEM.read_text()
anchor='static BOOL HFASemConditionalTarget(uint32_t w, uintptr_t pc, uintptr_t *target) {'
if anchor not in s: raise SystemExit('helper anchor missing')
if 'HFASemSTLR64' not in s:
    h=r'''
static BOOL HFASemBLTarget(uint32_t w, uintptr_t pc, uintptr_t *target){
    if((w&0xFC000000u)!=0x94000000u)return NO;
    int64_t imm=HFASemSignExtend(w&0x03FFFFFFu,26)<<2;
    if(target)*target=(uintptr_t)((int64_t)pc+imm);return YES;
}
static BOOL HFASemStrXReg(uint32_t w,unsigned *rt,unsigned *rn,unsigned *rm,unsigned *shift){
    if((w&0xFFE00C00u)!=0xF8200800u)return NO;
    if(((w>>13)&7u)!=3u)return NO;
    if(rt)*rt=w&31u;if(rn)*rn=(w>>5)&31u;if(rm)*rm=(w>>16)&31u;if(shift)*shift=((w>>12)&1u)?3u:0u;return YES;
}
static BOOL HFASemSTLR64(uint32_t w,unsigned *rt,unsigned *rn){if((w&0xFFFFFC00u)!=0xC89FFC00u)return NO;if(rt)*rt=w&31u;if(rn)*rn=(w>>5)&31u;return YES;}
static BOOL HFASemLDAR64(uint32_t w,unsigned *rt,unsigned *rn){if((w&0xFFFFFC00u)!=0xC8DFFC00u)return NO;if(rt)*rt=w&31u;if(rn)*rn=(w>>5)&31u;return YES;}
static BOOL HFASemLDAXR64(uint32_t w,unsigned *rt,unsigned *rn){if((w&0xFFFFFC00u)!=0xC85FFC00u)return NO;if(rt)*rt=w&31u;if(rn)*rn=(w>>5)&31u;return YES;}
static BOOL HFASemSTLXR64(uint32_t w,unsigned *status,unsigned *rt,unsigned *rn){if((w&0xFFE0FC00u)!=0xC800FC00u)return NO;if(status)*status=(w>>16)&31u;if(rt)*rt=w&31u;if(rn)*rn=(w>>5)&31u;return YES;}
static NSString *HFASemFPPrecision(uint32_t w){return (w&0x00400000u)?@"float64":@"float32";}
'''
    s=s.replace(anchor,h+anchor,1)

a,b=function_span(s,'HFASemanticAnalyzeReplacementBounded')
fn=s[a:b]
old='''    NSMutableArray *callbacks=[NSMutableArray array];\n    NSMutableArray *ops=[NSMutableArray array];\n    NSMutableSet *seenCapture=[NSMutableSet set];'''
new='''    NSMutableArray *callbacks=[NSMutableArray array];\n    NSMutableArray *ops=[NSMutableArray array];\n    NSMutableArray *helperCalls=[NSMutableArray array];\n    NSMutableSet *seenCapture=[NSMutableSet set];\n    BOOL hasReachableReturn=NO;'''
if old not in fn: raise SystemExit('vars anchor missing')
fn=fn.replace(old,new,1)
fn=fn.replace('if(HFASemConditional(w))conditional=YES;','if(HFASemConditional(w))conditional=YES;if(HFASemRET(w)){hasReachableReturn=YES;continue;}',1)
fn=fn.replace('BOOL arg=(rn<8||rm<8)&&!callsOriginal;','BOOL arg=(rd<8)&&!callsOriginal;',2)

store='''        if(HFASemStrX(w,&rd,&rn,&off)){\n            uintptr_t dst=addrKnown[rn]?addr[rn]+off:0;'''
extra=r'''        unsigned ar=0,ab=0,as=0,ix=0,sh=0;
        if(HFASemLDAR64(w,&ar,&ab)||HFASemLDAXR64(w,&ar,&ab)){receiverTaint[ar]=NO;addrKnown[ar]=NO;continue;}
        if(HFASemSTLR64(w,&ar,&ab)||HFASemSTLXR64(w,&as,&ar,&ab)){
            uintptr_t dst=addrKnown[ab]?addr[ab]:0;
            if(dst&&dst!=originalSlot&&HFASemWritable(dst,image)&&receiverTaint[ar]){
                NSString *key=[NSString stringWithFormat:@"%u:%llX:a",receiverOffset[ar],(unsigned long long)(dst-image.base)];
                if(![seenCapture containsObject:key]){[seenCapture addObject:key];[captures addObject:@{@"source":receiverOffset[ar]?@"subobject":@"receiver",@"fieldOffset":[NSString stringWithFormat:@"0x%X",receiverOffset[ar]],@"storeRVA":HFASemRVA(dst,image),@"storeKind":@"atomic"}];}
            }continue;
        }
        if(HFASemStrXReg(w,&rd,&rn,&ix,&sh)){
            uintptr_t base=addrKnown[rn]?addr[rn]:0;
            if(base&&base!=originalSlot&&HFASemWritable(base,image)&&receiverTaint[rd]){
                NSString *key=[NSString stringWithFormat:@"%u:%llX:i",receiverOffset[rd],(unsigned long long)(base-image.base)];
                if(![seenCapture containsObject:key]){[seenCapture addObject:key];[captures addObject:@{@"source":receiverOffset[rd]?@"subobject":@"receiver",@"fieldOffset":[NSString stringWithFormat:@"0x%X",receiverOffset[rd]],@"storeRVA":HFASemRVA(base,image),@"storeKind":@"indexed",@"indexRegister":@(ix),@"indexShift":@(sh)}];}
            }continue;
        }
'''
if store not in fn: raise SystemExit('store anchor missing')
fn=fn.replace(store,extra+store,1)

fp='''if(fp){BOOL ret=fpReturnTaint[rn]||fpReturnTaint[rm];BOOL arg=(rd<8)&&!callsOriginal;fpReturnTaint[rd]=ret;'''
if fp not in fn: raise SystemExit('fp anchor missing')
fn=fn.replace(fp,fp+'NSString *precision=HFASemFPPrecision(w);',1)
fn=fn.replace('@"phase":@"before-original",@"rva":HFASemRVA(pc,image)}];}continue;}','@"phase":@"before-original",@"argumentIndex":@(rd),@"rva":HFASemRVA(pc,image)}];}continue;}',1)
fn=fn.replace('@"op":fp,@"phase":@"after-original",@"rva":HFASemRVA(pc,image)','@"op":fp,@"phase":@"after-original",@"precision":precision,@"rva":HFASemRVA(pc,image)',1)
fn=fn.replace('@"op":fp,@"phase":@"before-original",@"rva":HFASemRVA(pc,image)','@"op":fp,@"phase":@"before-original",@"precision":precision,@"argumentIndex":@(rd),@"rva":HFASemRVA(pc,image)',1)

blr='''        unsigned br=0;\n        if(HFASemBLR(w,&br)){'''
if blr not in fn: raise SystemExit('blr anchor missing')
fn=fn.replace(blr,'''        uintptr_t directTarget=0;if(HFASemBLTarget(w,pc,&directTarget)){if(directTarget>=image.textStart&&directTarget<image.textEnd)[helperCalls addObject:@{@"targetRVA":HFASemRVA(directTarget,image),@"callSiteRVA":HFASemRVA(pc,image)}];continue;}\n        unsigned br=0;\n        if(HFASemBLR(w,&br)){''',1)

oldclass='''    unsigned returnTransforms=(returnMul?1u:0u)+(returnDiv?1u:0u)+(returnSelect?1u:0u);'''
if oldclass not in fn: raise SystemExit('class anchor missing')
fn=fn.replace(oldclass,'''    unsigned returnTransforms=(returnMul?1u:0u)+(returnDiv?1u:0u)+(returnSelect?1u:0u);\n    unsigned argumentTransforms=(argMul?1u:0u)+(argDiv?1u:0u);''',1)
fn=fn.replace('else if(argMul)semantic=@"argument-multiplier";\n    else if(argDiv)semantic=@"argument-divider";','else if(argumentTransforms>1)semantic=@"argument-transform";\n    else if(argMul)semantic=@"argument-multiplier";\n    else if(argDiv)semantic=@"argument-divider";',1)
fn=fn.replace('else if(sub)semantic=@"subobject-receiver-capture";\n    else if(direct)semantic=@"receiver-capture";','else if(sub&&helperCalls.count)semantic=@"subobject-receiver-capture-with-helper";\n    else if(direct&&helperCalls.count)semantic=@"receiver-capture-with-helper";\n    else if(sub)semantic=@"subobject-receiver-capture";\n    else if(direct)semantic=@"receiver-capture";',1)
ret='''        @"tailCallsOriginal":@(tailCallsOriginal)\n    };'''
if ret not in fn: raise SystemExit('return anchor missing')
fn=fn.replace(ret,'''        @"tailCallsOriginal":@(tailCallsOriginal),\n        @"hasReachableReturn":@(hasReachableReturn),\n        @"helperCalls":helperCalls?:@[]\n    };''',1)
s=s[:a]+fn+s[b:]
s=s.replace('HFAMap_RuntimeAnalyzer_v0342_stage.log','HFAMap_RuntimeAnalyzer_v035_stage.log')
s=s.replace('V0342-','V035-')
SEM.write_text(s)

# Truth gate: this layer is instruction-class based, not title/RVA based.
for forbidden in ['0x2D98AC8','0x2D9887C']:
    if forbidden in s: raise SystemExit('fixed target leaked into generic semantic layer')
for required in ['HFASemStrXReg','HFASemSTLR64','HFASemSTLXR64','argument-transform','receiver-capture-with-helper','helperCalls']:
    if required not in s: raise SystemExit('missing '+required)
print('v0.3.5 generic semantic coverage applied')
