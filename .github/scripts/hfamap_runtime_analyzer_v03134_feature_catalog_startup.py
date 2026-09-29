from pathlib import Path

FAMILY=Path('hfamap/src/HFAMapFamilyRuntimeResolver.m')
TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')

f=FAMILY.read_text()

# Small, stable field anchors: prior generators may reformat or extend the context.
anchor='    NSMutableSet<NSValue *> *seenTargets;'
if anchor not in f: raise SystemExit('catalog seenTargets anchor missing')
f=f.replace(anchor,anchor+'\n    NSMutableSet<NSValue *> *seenCatalogObjects;',1)
anchor='    unsigned featureControls;'
if anchor not in f: raise SystemExit('catalog featureControls anchor missing')
f=f.replace(anchor,anchor+'\n    unsigned catalogFeatures;\n    unsigned hiddenFeatures;',1)

owner_sig='static void HFAFamilyProfileOwner(HFAFamilyContext *context, id owner, const char *origin) {'
if owner_sig not in f: raise SystemExit('catalog owner signature missing')
helpers=r'''static BOOL HFAFamilyCatalogMark(HFAFamilyContext *context,id object){
    if(!context||!object)return NO;NSValue *key=[NSValue valueWithPointer:(__bridge const void *)object];
    if([context->seenCatalogObjects containsObject:key])return NO;[context->seenCatalogObjects addObject:key];return YES;
}
static BOOL HFAFamilyLooksLikeFeatureObject(id object,const char *image){
    if(!object)return NO;Class cls=object_getClass(object);if(!HFAFamilyClassBelongsToImage(cls,image))return NO;
    return HFAFamilyHasSelector(cls,"identifier")&&HFAFamilyHasSelector(cls,"type");
}
static void HFAFamilyCatalogObject(HFAFamilyContext *context,id object,const char *origin,unsigned depth){
    if(!context||!object||depth>6||!HFAFamilyCatalogMark(context,object))return;
    if(HFAFamilyLooksLikeFeatureObject(object,context->image)){
        NSString *identifier=HFAFamilyStringGetter(object,"identifier");NSString *label=HFAFamilyLabel(object);
        BOOL visible=NO;if([object isKindOfClass:UIView.class]){@try{UIView *v=(UIView*)object;visible=!v.hidden&&v.alpha>0.001&&v.window!=nil;}@catch(__unused id ex){}}
        if(identifier.length){NSString *stableLabel=label.length?label:identifier;HFARegisterFeatureDefinition(stableLabel.UTF8String,identifier.UTF8String);context->catalogFeatures++;if(!visible)context->hiddenFeatures++;
            HFAFamilyLog([NSString stringWithFormat:@"[V03134-FEATURE-CATALOG] origin=%s class=%s identifier=%@ label=%@ visibility=%@ object=%p",origin?:"?",class_getName(object_getClass(object))?:"?",identifier,stableLabel,visible?@"visible":@"hidden-or-not-instantiated",object]);
        }
    }
    if([object isKindOfClass:NSArray.class]){NSArray *a=object;NSUInteger n=MIN(a.count,(NSUInteger)128);for(NSUInteger i=0;i<n;i++)HFAFamilyCatalogObject(context,a[i],"array-item",depth+1);return;}
    if([object isKindOfClass:NSSet.class]){NSUInteger n=0;for(id item in (NSSet*)object){if(n++>=128)break;HFAFamilyCatalogObject(context,item,"set-item",depth+1);}return;}
    if([object isKindOfClass:NSDictionary.class]){NSUInteger n=0;for(id key in (NSDictionary*)object){if(n++>=128)break;id value=((NSDictionary*)object)[key];HFAFamilyCatalogObject(context,value,"dict-value",depth+1);}return;}
    Class cls=object_getClass(object);if(!HFAFamilyClassBelongsToImage(cls,context->image))return;
    for(Class cursor=cls;cursor&&cursor!=NSObject.class;cursor=class_getSuperclass(cursor)){
        unsigned count=0;Ivar *ivars=class_copyIvarList(cursor,&count);if(count>96)count=96;
        for(unsigned i=0;ivars&&i<count;i++){const char *type=ivar_getTypeEncoding(ivars[i]);if(!type||type[0]!='@')continue;id value=nil;@try{value=object_getIvar(object,ivars[i]);}@catch(__unused id ex){value=nil;}if(value)HFAFamilyCatalogObject(context,value,"owner-ivar",depth+1);}free(ivars);
    }
}
'''
if 'HFAFamilyCatalogObject' not in f:f=f.replace(owner_sig,helpers+'\n'+owner_sig,1)

old='''static void HFAFamilyProfileOwner(HFAFamilyContext *context, id owner, const char *origin) {\n    if (!context || !owner || !HFAFamilyMarkTarget(context, owner)) return;'''
new='''static void HFAFamilyProfileOwner(HFAFamilyContext *context, id owner, const char *origin) {\n    if (!context || !owner) return;\n    HFAFamilyCatalogObject(context, owner, origin ?: "owner", 0);\n    if (!HFAFamilyMarkTarget(context, owner)) return;'''
if old not in f: raise SystemExit('catalog profile body anchor missing')
f=f.replace(old,new,1)

# UI controls feed the same catalog. Existing normal + identifier-fallback
# registration remains untouched.
anchor='            HFAGenericMenuObserveObject(view, "family-ui-control");'
if anchor not in f: raise SystemExit('catalog UI observe anchor missing')
f=f.replace(anchor,'            HFAFamilyCatalogObject(context, view, "family-ui-control", 0);\n'+anchor,1)

anchor='        context.seenTargets = [NSMutableSet set];'
if anchor not in f: raise SystemExit('catalog init anchor missing')
f=f.replace(anchor,anchor+'\n        context.seenCatalogObjects = [NSMutableSet set];',1)

# Additional summary line avoids relying on the exact legacy end-log format.
anchor='        HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 扫描完成：菜单控件 %u，动作 %u",'
if anchor not in f: raise SystemExit('catalog summary anchor missing')
f=f.replace(anchor,'        HFAFamilyLog([NSString stringWithFormat:@"[V03134-FEATURE-CATALOG-SUMMARY] catalogFeatures=%u hiddenFeatures=%u", context.catalogFeatures, context.hiddenFeatures]);\n'+anchor,1)
FAMILY.write_text(f)

# Startup/static-support ownership from Mach-O __mod_init_func provenance.
t=TRACE.read_text()
sig='static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates)'
pos=t.find(sig)
if pos<0: raise SystemExit('startup bridge anchor missing')
helpers=r'''static NSSet *HFA03134ModInitFunctions(HFA03134MenuLayout l){
    if(!l.base)return [NSSet set];const struct mach_header_64 *h=(const struct mach_header_64*)l.base;NSMutableSet *out=[NSMutableSet set];const uint8_t *cur=(const uint8_t*)(h+1);
    for(uint32_t c=0;c<h->ncmds;c++){const struct load_command *lc=(const struct load_command*)cur;if(!lc->cmdsize)break;if(lc->cmd==LC_SEGMENT_64){const struct segment_command_64 *seg=(const struct segment_command_64*)cur;const struct section_64 *sec=(const struct section_64*)(seg+1);for(uint32_t q=0;q<seg->nsects;q++){if(strncmp(sec[q].sectname,"__mod_init_func",16))continue;uintptr_t a=(uintptr_t)l.slide+(uintptr_t)sec[q].addr,e=a+(uintptr_t)sec[q].size;for(uintptr_t p=a;p+sizeof(uintptr_t)<=e;p+=sizeof(uintptr_t)){uintptr_t fn=0;if(!HFAReadable(p,sizeof(fn)))break;memcpy(&fn,(void*)p,sizeof(fn));if(fn)[out addObject:@(fn)];}}}cur+=lc->cmdsize;}return out;
}
static NSDictionary *HFA03134StartupOwnership(NSDictionary *backend,NSDictionary *registrationEvidence,HFA03134MenuLayout l,NSSet *modInit){
    if(!registrationEvidence.count||!l.base||!modInit.count)return nil;NSString *rv=[registrationEvidence[@"ownerFunctionRVA"] description];if(!rv.length)return nil;uint64_t off=strtoull(rv.UTF8String,NULL,0);if(!off)return nil;uintptr_t fn=l.base+(uintptr_t)off;if(![modInit containsObject:@(fn)])return nil;
    return @{@"ownerClass":@"startup-owned",@"source":@"mach-o-mod-init",@"constructorRVA":rv,@"backendId":backend[@"backendId"]?:@0};
}
'''
if 'HFA03134StartupOwnership' not in t:t=t[:pos]+helpers+'\n'+t[pos:]

anchor='    NSArray *objectTableRanges=haveRegistrationLayout?HFA03134StaticDataRanges(registrationLayout):@[];'
if anchor not in t: raise SystemExit('startup objectTableRanges anchor missing')
t=t.replace(anchor,anchor+'\n    NSSet *modInitFunctions=haveRegistrationLayout?HFA03134ModInitFunctions(registrationLayout):[NSSet set];',1)

old='''        else{if([reason isEqual:@"unowned-static-backend"]&&cid.length)reason=@"orphan-static-feature-cluster";e[@"status"]=@"excluded";e[@"reason"]=reason;[ledger addObject:e];HFALog("[STATIC-BRIDGE] backend=%u family=%s cluster=%s target=%s offset=%s canonicalRVA=%s status=excluded reason=%s\\n",[e[@"analyzerBackendId"] unsignedIntValue],[e[@"family"] UTF8String]?:"?",cid.UTF8String?:"-",[e[@"target"] UTF8String]?:"?",[e[@"offset"] UTF8String]?:"?",[e[@"canonicalRVA"] UTF8String]?:"?",reason.UTF8String?:"?");}'''
new='''        else{NSDictionary *startupRegEv=registrationEvidenceByBackend[[be[@"backendId"] description]?:@""];NSDictionary *startup=nil;if([reason isEqual:@"unowned-static-backend"]||[reason isEqual:@"orphan-static-feature-cluster"])startup=HFA03134StartupOwnership(be,startupRegEv,registrationLayout,modInitFunctions);if(startup){e[@"ownershipSource"]=@"mach-o-mod-init";e[@"ownerClass"]=@"startup-owned";e[@"ownershipEvidence"]=startup;e[@"status"]=@"owned-support";e[@"reason"]=@"startup-static-support";[ledger addObject:e];HFALog("[V03134-STARTUP-OWNERSHIP] backend=%u constructor=%s target=%s offset=%s status=startup-owned\\n",[e[@"analyzerBackendId"] unsignedIntValue],[[startup[@"constructorRVA"] description] UTF8String]?:"?",[e[@"target"] UTF8String]?:"?",[e[@"offset"] UTF8String]?:"?");}else{if([reason isEqual:@"unowned-static-backend"]&&cid.length)reason=@"orphan-static-feature-cluster";e[@"status"]=@"excluded";e[@"reason"]=reason;[ledger addObject:e];HFALog("[STATIC-BRIDGE] backend=%u family=%s cluster=%s target=%s offset=%s canonicalRVA=%s status=excluded reason=%s\\n",[e[@"analyzerBackendId"] unsignedIntValue],[e[@"family"] UTF8String]?:"?",cid.UTF8String?:"-",[e[@"target"] UTF8String]?:"?",[e[@"offset"] UTF8String]?:"?",[e[@"canonicalRVA"] UTF8String]?:"?",reason.UTF8String?:"?");}}'''
if old not in t: raise SystemExit('startup exclusion anchor missing')
t=t.replace(old,new,1)
TRACE.write_text(t)

for path,markers in [(FAMILY,['[V03134-FEATURE-CATALOG]','hidden-or-not-instantiated','catalogFeatures','hiddenFeatures']),(TRACE,['HFA03134ModInitFunctions','HFA03134StartupOwnership','[V03134-STARTUP-OWNERSHIP]','startup-static-support'])]:
    out=path.read_text()
    for marker in markers:
        if marker not in out: raise SystemExit('missing catalog/startup marker '+marker)
print('v0.3.13.4 hidden feature catalog + startup ownership applied')
