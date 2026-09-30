from pathlib import Path

P=Path('hfamap/src/HFAMapRuntimeModificationTruth.m')
s=P.read_text()

old='BOOL targetExec=target&&HFATRange(target,4,YES),replacementExec=replacement&&HFATRange(replacement,4,YES),originalExec=original&&HFATRange(original,4,YES);BOOL installed=targetExec&&replacementExec&&slotReadable&&original!=0&&originalExec;'
new='BOOL targetExec=target&&HFATRange(target,4,YES),replacementExec=replacement&&HFATRange(replacement,4,YES),originalExec=original&&HFATRange(original,4,YES);BOOL installed=targetExec&&replacementExec&&slotReadable&&original!=0;'
if old not in s: raise SystemExit('hook installed anchor missing')
s=s.replace(old,new,1)

old='NSMutableArray *patches=[NSMutableArray array],*hooks=[NSMutableArray array],*startup=[NSMutableArray array];NSMutableSet *menuIds=[NSMutableSet set];NSUInteger enabled=0,original=0,unknown=0,unreadable=0;'
new='NSMutableArray *patches=[NSMutableArray array],*hooks=[NSMutableArray array],*startup=[NSMutableArray array];NSMutableSet *menuIds=[NSMutableSet set],*startupGroups=[NSMutableSet set];NSUInteger enabled=0,original=0,unknown=0,unreadable=0;'
if old not in s: raise SystemExit('truth collection anchor missing')
s=s.replace(old,new,1)

old='if([[e[@"ownerClass"] description] isEqual:@"startup-owned"])[startup addObject:v];'
new='if([[e[@"ownerClass"] description] isEqual:@"startup-owned"]){[startup addObject:v];NSDictionary *oe=[e[@"ownershipEvidence"] isKindOfClass:NSDictionary.class]?e[@"ownershipEvidence"]:@{};NSString *group=[oe[@"constructorRVA"] description];if(!group.length)group=[NSString stringWithFormat:@"backend-%@",e[@"analyzerBackendId"]?:@0];[startupGroups addObject:group];}'
if old not in s: raise SystemExit('startup group anchor missing')
s=s.replace(old,new,1)

old='NSUInteger menuFeatureCount=menuIds.count+hooks.count,startupFeatureCount=startup.count,effectiveFeatureCount=menuFeatureCount+startupFeatureCount;'
new='NSUInteger menuFeatureCount=menuIds.count+hooks.count,startupFeatureCount=startupGroups.count,effectiveFeatureCount=menuFeatureCount+startupFeatureCount;'
if old not in s: raise SystemExit('feature count anchor missing')
s=s.replace(old,new,1)

old='@"startupFeatureCount":@(startupFeatureCount),@"effectiveFeatureCount":@(effectiveFeatureCount),@"fixedPatchSiteCount":@(patches.count)'
new='@"startupFeatureCount":@(startupFeatureCount),@"startupModificationCount":@(startup.count),@"effectiveFeatureCount":@(effectiveFeatureCount),@"fixedPatchSiteCount":@(patches.count)'
if old not in s: raise SystemExit('truth output count anchor missing')
s=s.replace(old,new,1)

P.write_text(s)
for token in ['startupGroups','startupModificationCount','original!=0;']:
    if token not in s: raise SystemExit('truth semantics fix missing '+token)
print('v0.3.13.13 truth semantics fix applied')
