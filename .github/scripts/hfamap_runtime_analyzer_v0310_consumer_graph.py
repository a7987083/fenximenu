from pathlib import Path

ROOT=Path('hfamap')
SRC=ROOT/'src'/'HFAMapRuntimeAnalyzerV02.m'
SEM=ROOT/'src'/'HFARuntimeSemanticAnalyzer.m'
UI=ROOT/'src'/'HFAMapCyberUI.m'
s=SRC.read_text()
scan='unsigned HFAAnalyzerV02ScanSelectedImage(void)'
pos=s.find(scan)
if pos<0: raise SystemExit('v0310 scan entry missing')

if 'HFAV0310ConsumerGraph' not in s:
    helper=r'''
static NSArray *HFAV0310FeatureNotifications(NSDictionary *f){NSMutableOrderedSet *names=[NSMutableOrderedSet orderedSet];for(NSDictionary *a in [f[@"actions"] isKindOfClass:NSArray.class]?f[@"actions"]:@[]){NSDictionary *d=[a[@"dispatcher"] isKindOfClass:NSDictionary.class]?a[@"dispatcher"]:nil;for(NSDictionary *n in [d[@"notifications"] isKindOfClass:NSArray.class]?d[@"notifications"]:@[]){NSString *name=[n[@"name"] isKindOfClass:NSString.class]?n[@"name"]:nil;if(name.length)[names addObject:name];}}for(NSDictionary *b in [f[@"observerBridges"] isKindOfClass:NSArray.class]?f[@"observerBridges"]:@[]){NSDictionary *r=[b[@"observerRegistration"] isKindOfClass:NSDictionary.class]?b[@"observerRegistration"]:nil;NSString *name=[r[@"name"] isKindOfClass:NSString.class]?r[@"name"]:nil;if(name.length)[names addObject:name];}return names.array?:@[];}
static NSDictionary *HFAV0310ConsumerGraph(NSArray *runtime,const char *selectedImage,HFAV02Layout l){NSString *selected=selectedImage?[NSString stringWithUTF8String:selectedImage]:@"";NSMutableArray *features=[NSMutableArray array];NSUInteger notificationCount=0,resolvedCallbacks=0,candidateCallbacks=0,helperCount=0;
    for(NSDictionary *f in runtime?:@[]){NSString *identifier=[f[@"identifier"] isKindOfClass:NSString.class]?f[@"identifier"]:nil;if(!identifier.length)continue;NSArray *notifications=HFAV0310FeatureNotifications(f);notificationCount+=notifications.count;NSMutableArray *callbacks=[NSMutableArray array];NSMutableArray *candidates=[NSMutableArray array];
        for(NSDictionary *b in [f[@"observerBridges"] isKindOfClass:NSArray.class]?f[@"observerBridges"]:@[]){NSDictionary *r=[b[@"observerRegistration"] isKindOfClass:NSDictionary.class]?b[@"observerRegistration"]:nil;NSDictionary *cb=[r[@"callback"] isKindOfClass:NSDictionary.class]?r[@"callback"]:nil;if(cb){NSString *im=[cb[@"image"] isKindOfClass:NSString.class]?cb[@"image"]:nil;NSString *rv=[cb[@"rva"] isKindOfClass:NSString.class]?cb[@"rva"]:nil;NSMutableDictionary *x=[cb mutableCopy];if(!im.length||[im isEqual:selected]){NSDictionary *ev=HFAV039SemanticAtRVA(rv,l);x[@"semanticType"]=ev[@"semanticType"]?:@"unknown-runtime";x[@"stateAccessCount"]=@([[ev[@"stateAccesses"] isKindOfClass:NSArray.class]?ev[@"stateAccesses"]:@[] count]);NSArray *hc=[ev[@"helperCalls"] isKindOfClass:NSArray.class]?ev[@"helperCalls"]:@[];x[@"helperCount"]=@(hc.count);helperCount+=MIN((NSUInteger)6,hc.count);NSMutableArray *helpers=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];for(NSDictionary *h in hc){if(helpers.count>=6)break;NSString *hr=[h[@"targetRVA"] isKindOfClass:NSString.class]?h[@"targetRVA"]:nil;if(!hr.length||[seen containsObject:hr])continue;[seen addObject:hr];NSDictionary *hev=HFAV039SemanticAtRVA(hr,l);[helpers addObject:@{@"rva":hr,@"semanticType":hev[@"semanticType"]?:@"unknown-runtime",@"stateAccessCount":@([[hev[@"stateAccesses"] isKindOfClass:NSArray.class]?hev[@"stateAccesses"]:@[] count])}];}if(helpers.count)x[@"helpers"]=helpers;}[callbacks addObject:x];resolvedCallbacks++;}
            for(NSDictionary *c in [r[@"blockInvokeCandidates"] isKindOfClass:NSArray.class]?r[@"blockInvokeCandidates"]:@[]){NSMutableDictionary *x=[c mutableCopy];x[@"confidence"]=@"candidate";[candidates addObject:x];candidateCallbacks++;}
        }
        NSMutableDictionary *g=[@{@"identifier":identifier,@"notifications":notifications,@"callbacks":callbacks,@"blockInvokeCandidates":candidates} mutableCopy];if([f[@"title"] isKindOfClass:NSString.class])g[@"title"]=f[@"title"];if(callbacks.count)g[@"status"]=@"resolved-callback";else if(candidates.count)g[@"status"]=@"candidate-only";else if(notifications.count)g[@"status"]=@"notification-only";else g[@"status"]=@"no-notification";[features addObject:g];
    }
    HFAV02Log([NSString stringWithFormat:@"[V0310-CONSUMER-GRAPH] features=%lu notifications=%lu resolvedCallbacks=%lu candidates=%lu helpers=%lu",(unsigned long)features.count,(unsigned long)notificationCount,(unsigned long)resolvedCallbacks,(unsigned long)candidateCallbacks,(unsigned long)helperCount]);return @{@"features":features,@"featureCount":@(features.count),@"notificationCount":@(notificationCount),@"resolvedCallbackCount":@(resolvedCallbacks),@"candidateCallbackCount":@(candidateCallbacks),@"helperCount":@(helperCount),@"policy":@"diagnostic-only-unless-exact-state-binding"};
}
'''
    s=s[:pos]+helper+'\n'+s[pos:]

anchor='NSDictionary *evidence38=HFAV038EvidenceSnapshot();NSArray *runtime=[evidence38[@"features"] isKindOfClass:NSArray.class]?evidence38[@"features"]:@[];NSString *readiness38=[evidence38[@"status"] isKindOfClass:NSString.class]?evidence38[@"status"]:@"pending";'
if anchor not in s: raise SystemExit('v0310 evidence anchor missing')
s=s.replace(anchor,anchor+'NSDictionary *consumerGraph310=HFAV0310ConsumerGraph(runtime,image,l);',1)

root='@"evidenceReadiness":evidence38'
if root not in s: raise SystemExit('v0310 root anchor missing')
s=s.replace(root,root+',@"consumerGraph":consumerGraph310',1)

s=s.replace('com.hfa.runtime-analyzer/v0.3.9','com.hfa.runtime-analyzer/v0.3.10',1)
s=s.replace('HFAEnableIL2CPPEnrichmentV039','HFAEnableIL2CPPEnrichmentV0310')
out='NSString *p39=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v039.json");'
if out not in s: raise SystemExit('v0310 output anchor missing')
s=s.replace(out,'NSString *p310=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v0310.json");'+out,1)
write='[json writeToFile:p39 atomically:YES];[json writeToFile:p38 atomically:YES];'
if write not in s: raise SystemExit('v0310 write anchor missing')
s=s.replace(write,'[json writeToFile:p310 atomically:YES];'+write,1)
SRC.write_text(s)

SEM.write_text(SEM.read_text().replace('HFAMap_RuntimeAnalyzer_v039_stage.log','HFAMap_RuntimeAnalyzer_v0310_stage.log'))
UI.write_text(UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.9 ExactStateXrefConsumerResolver','HFAMap RuntimeAnalyzer v0.3.10 NotificationConsumerGraph',2).replace('com.hfa.runtime-analyzer.v039','com.hfa.runtime-analyzer.v0310'))

ss=SRC.read_text()
for required in ['HFAV0310ConsumerGraph','[V0310-CONSUMER-GRAPH]','diagnostic-only-unless-exact-state-binding','HFAMap_RuntimeAnalyzer_v0310.json','com.hfa.runtime-analyzer/v0.3.10','HFAEnableIL2CPPEnrichmentV0310']:
    if required not in ss: raise SystemExit('missing '+required)
for forbidden in ['0x2D98AC8','0x2D9887C','0x2E25904','Duck Survival','Aniimo','ProDragon']:
    if forbidden in ss: raise SystemExit('sample-specific token leaked into v0310 consumer graph')
print('v0.3.10 notification consumer graph applied')
