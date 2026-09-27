from pathlib import Path

P=Path('hfamap/src/HFAMap5MDispatcherResolver.m')
s=P.read_text()
name='HFA5MImageObserverBridgesForNotification'
needle='static NSArray *'+name+'('
start=s.find(needle)
if start<0: raise SystemExit('v0311 notification function missing')
brace=s.find('{',start)
if brace<0: raise SystemExit('v0311 notification brace missing')
depth=0;end=-1
for i in range(brace,len(s)):
    if s[i]=='{': depth+=1
    elif s[i]=='}':
        depth-=1
        if depth==0:
            end=i+1;break
if end<0: raise SystemExit('v0311 notification function end missing')

helper=r'''
typedef struct { uintptr_t base,textStart,textEnd,selStart,selEnd; intptr_t slide; } HFA0311NotifyLayout;
static const char *HFA0311BaseName(const char *p){const char *q=p?strrchr(p,'/'):NULL;return q?q+1:(p?p:"");}
static BOOL HFA0311NotifyLayoutForImage(NSString *image,HFA0311NotifyLayout *out){if(!image.length||!out)return NO;uint32_t n=_dyld_image_count();for(uint32_t i=0;i<n;i++){const char *p=_dyld_get_image_name(i);if(!p||strcmp(HFA0311BaseName(p),image.UTF8String))continue;const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header(i);if(!h||h->magic!=MH_MAGIC_64)return NO;HFA0311NotifyLayout l={0};l.base=(uintptr_t)h;l.slide=_dyld_get_image_vmaddr_slide(i);const uint8_t *cur=(const uint8_t*)(h+1);for(uint32_t c=0;c<h->ncmds;c++){const struct load_command *lc=(const struct load_command*)cur;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *seg=(const struct segment_command_64*)cur;const struct section_64 *sec=(const struct section_64*)(seg+1);for(uint32_t q=0;q<seg->nsects;q++){uintptr_t a=(uintptr_t)l.slide+(uintptr_t)sec[q].addr,e=a+(uintptr_t)sec[q].size;if(e<=a)continue;if(!strncmp(sec[q].sectname,"__text",16)){l.textStart=a;l.textEnd=e;}else if(!strncmp(sec[q].sectname,"__objc_selrefs",16)){l.selStart=a;l.selEnd=e;}}}cur+=lc->cmdsize;}*out=l;return l.textStart&&l.textEnd>l.textStart&&l.selStart&&l.selEnd>l.selStart;}return NO;}
static BOOL HFA0311DecodeLDRX(uint32_t w,unsigned *rn,uint64_t *off){if((w&0xFFC00000u)!=0xF9400000u)return NO;if(rn)*rn=(w>>5)&31u;if(off)*off=(uint64_t)((w>>10)&0xFFFu)*8u;return YES;}
static NSArray *HFA0311SelectorRefAddresses(HFA0311NotifyLayout l,const char *selectorName){if(!selectorName||!*selectorName)return @[];NSMutableArray *out=[NSMutableArray array];for(uintptr_t p=l.selStart;p+sizeof(uintptr_t)<=l.selEnd;p+=sizeof(uintptr_t)){uintptr_t v=0;memcpy(&v,(void*)p,sizeof(v));if(!v)continue;const char *n=sel_getName((SEL)v);if(n&&!strcmp(n,selectorName))[out addObject:@((unsigned long long)p)];}return out;}
static NSArray *HFA0311SelectorTextXrefs(HFA0311NotifyLayout l,NSArray *refs){if(!refs.count)return @[];uintptr_t vals[32]={0};NSUInteger rc=MIN((NSUInteger)32,refs.count);for(NSUInteger i=0;i<rc;i++)vals[i]=(uintptr_t)[refs[i] unsignedLongLongValue];NSMutableOrderedSet *hits=[NSMutableOrderedSet orderedSet];NSUInteger count=(l.textEnd-l.textStart)/4;const uint32_t *w=(const uint32_t*)l.textStart;for(NSUInteger i=0;i<count;i++){unsigned reg=0;uintptr_t pc=l.textStart+i*4,page=0;if(!HFA5MDecodeADRP(w[i],pc,&reg,&page))continue;for(NSUInteger q=i+1;q<count&&q<=i+3;q++){unsigned rn=0;uint64_t off=0;if(HFA0311DecodeLDRX(w[q],&rn,&off)&&rn==reg){uintptr_t target=page+(uintptr_t)off;for(NSUInteger r=0;r<rc;r++)if(vals[r]==target){[hits addObject:@((unsigned long long)(l.textStart+q*4))];break;}}unsigned rd=0;uint64_t imm=0;if(HFA5MDecodeADDX(w[q],&rd,&rn,&imm)&&rn==reg){uintptr_t target=page+(uintptr_t)imm;for(NSUInteger r=0;r<rc;r++)if(vals[r]==target){[hits addObject:@((unsigned long long)(l.textStart+q*4))];break;}}}}return hits.array?:@[];}
static NSArray *HFA0311MethodMetadataForImage(NSString *image,uintptr_t base){Class classes[768]={0};unsigned cc=HFAAppLocalCopyClassesForImage(image.UTF8String,classes,768);NSMutableArray *methods=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];for(unsigned ci=0;ci<cc&&ci<768;ci++){Class cls=classes[ci];if(!cls)continue;for(int pass=0;pass<2;pass++){Class owner=pass?object_getClass(cls):cls;if(!owner)continue;unsigned count=0;Method *ml=class_copyMethodList(owner,&count);for(unsigned mi=0;ml&&mi<count&&methods.count<4096;mi++){IMP imp=method_getImplementation(ml[mi]);uintptr_t a=(uintptr_t)imp;Dl_info di={0};if(!a||!dladdr((void*)a,&di)||!di.dli_fbase||(uintptr_t)di.dli_fbase!=base)continue;NSNumber *k=@((unsigned long long)a);if([seen containsObject:k])continue;[seen addObject:k];[methods addObject:@{@"address":k,@"owner":[NSValue valueWithPointer:(__bridge const void*)owner],@"selector":NSStringFromSelector(method_getName(ml[mi]))?:@"?",@"class":[NSString stringWithUTF8String:class_getName(cls)?:"?"]?:@"?"}];}free(ml);}}[methods sortUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){unsigned long long x=[a[@"address"] unsignedLongLongValue],y=[b[@"address"] unsignedLongLongValue];return x<y?NSOrderedAscending:(x>y?NSOrderedDescending:NSOrderedSame);}];return methods;}
static NSDictionary *HFA0311OwningMethod(uintptr_t pc,NSArray *methods){NSDictionary *best=nil;for(NSUInteger i=0;i<methods.count;i++){NSDictionary *m=methods[i];uintptr_t a=(uintptr_t)[m[@"address"] unsignedLongLongValue];if(a>pc)break;uintptr_t next=0;if(i+1<methods.count)next=(uintptr_t)[methods[i+1][@"address"] unsignedLongLongValue];if(pc>=a&&((next&&pc<next)||(!next&&pc-a<=0x4000u)))best=m;}return best;}
'''

replacement=r'''static NSArray *HFA5MImageObserverBridgesForNotification(NSString *image, NSString *notification) {
    if(!image.length||!notification.length)return @[];static NSMutableDictionary *cache=nil;NSString *key=[NSString stringWithFormat:@"%@|%@",image,notification];@synchronized([NSObject class]){if(!cache)cache=[NSMutableDictionary dictionary];NSArray *hit=cache[key];if(hit)return hit;}
    HFA0311NotifyLayout l={0};if(!HFA0311NotifyLayoutForImage(image,&l))return @[];NSArray *methods=HFA0311MethodMetadataForImage(image,l.base);NSMutableOrderedSet *pcs=[NSMutableOrderedSet orderedSet];
    const char *selectors[]={"addObserverForName:object:queue:usingBlock:","addObserver:selector:name:object:"};for(unsigned si=0;si<2;si++){NSArray *refs=HFA0311SelectorRefAddresses(l,selectors[si]);for(NSNumber *pc in HFA0311SelectorTextXrefs(l,refs))[pcs addObject:pc];}
    NSMutableArray *out=[NSMutableArray array];NSMutableSet *scanned=[NSMutableSet set];for(NSNumber *pn in pcs){uintptr_t pc=(uintptr_t)pn.unsignedLongLongValue;NSDictionary *m=HFA0311OwningMethod(pc,methods);if(!m)continue;NSNumber *addr=m[@"address"];if([scanned containsObject:addr])continue;[scanned addObject:addr];Class owner=(__bridge Class)[m[@"owner"] pointerValue];SEL sel=NSSelectorFromString(m[@"selector"]);IMP imp=(IMP)(uintptr_t)addr.unsignedLongLongValue;NSDictionary *scan=HFA5MScanMethod(owner,sel,imp);NSArray *regs=[scan[@"observerRegistrations"] isKindOfClass:NSArray.class]?scan[@"observerRegistrations"]:@[];for(NSDictionary *reg in regs){if(![[reg[@"name"] description] isEqual:notification])continue;NSMutableDictionary *bridge=[scan mutableCopy];bridge[@"observerRegistration"]=reg;bridge[@"observerSelector"]=reg[@"registrationSelector"]?:@"unknown";bridge[@"observerClass"]=m[@"class"]?:@"?";bridge[@"discovery"]=@"selector-xref-notification-registration";HFA5MAppendUnique(out,bridge,@[@"image",@"rva",@"observerSelector"]);if(out.count>=24)break;}if(out.count>=24)break;}
    HFA5MLog([NSString stringWithFormat:@"[V0311-NOTIFY-XREF] image=%@ notification=%@ methods=%lu selectorXrefs=%lu candidateMethods=%lu bridges=%lu",image,notification,(unsigned long)methods.count,(unsigned long)pcs.count,(unsigned long)scanned.count,(unsigned long)out.count]);NSArray *result=[out copy];@synchronized([NSObject class]){cache[key]=result;}return result;
}'''

s=s[:start]+helper+'\n'+replacement+s[end:]
P.write_text(s)
for required in ['HFA0311SelectorRefAddresses','HFA0311SelectorTextXrefs','selector-xref-notification-registration','[V0311-NOTIFY-XREF]']:
    if required not in s: raise SystemExit('missing '+required)
print('v0.3.11 notification selector-xref prefilter applied')
