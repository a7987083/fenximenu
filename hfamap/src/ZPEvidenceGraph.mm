#import "ZPEvidenceGraph.h"
#include <pthread.h>

static pthread_mutex_t gGraphLock=PTHREAD_MUTEX_INITIALIZER;
static NSMutableArray<NSDictionary*> *gNodes;
static NSMutableArray<NSDictionary*> *gEdges;
static NSUInteger gNodeCounter;
static const NSUInteger kMaxNodes=2048;
static const NSUInteger kMaxEdges=4096;

void ZPEvidenceGraphReset(void){
    pthread_mutex_lock(&gGraphLock);
    gNodes=[NSMutableArray array]; gEdges=[NSMutableArray array]; gNodeCounter=0;
    pthread_mutex_unlock(&gGraphLock);
}
NSString *ZPEvidenceGraphAddNode(NSString *kind,NSDictionary *attributes){
    if(!kind.length)return @"";
    pthread_mutex_lock(&gGraphLock);
    if(!gNodes)gNodes=[NSMutableArray array];
    NSString *node=[NSString stringWithFormat:@"n%lu",(unsigned long)++gNodeCounter];
    if(gNodes.count<kMaxNodes){NSMutableDictionary *r=[@{@"id":node,@"kind":kind} mutableCopy]; if(attributes)[r addEntriesFromDictionary:attributes]; [gNodes addObject:r];}
    pthread_mutex_unlock(&gGraphLock);
    return node;
}
void ZPEvidenceGraphAddEdge(NSString *fromNode,NSString *relation,NSString *toNode,NSDictionary *evidence){
    if(!fromNode.length||!relation.length||!toNode.length)return;
    pthread_mutex_lock(&gGraphLock);
    if(!gEdges)gEdges=[NSMutableArray array];
    if(gEdges.count<kMaxEdges){NSMutableDictionary *r=[@{@"from":fromNode,@"relation":relation,@"to":toNode} mutableCopy]; if(evidence.count)r[@"evidence"]=evidence; [gEdges addObject:r];}
    pthread_mutex_unlock(&gGraphLock);
}
NSDictionary *ZPEvidenceGraphSnapshot(void){
    pthread_mutex_lock(&gGraphLock);
    NSDictionary *r=@{@"schema":@"com.hfa.zpatchig.evidence-graph/v1",@"nodes":[gNodes copy]?:@[],@"edges":[gEdges copy]?:@[]};
    pthread_mutex_unlock(&gGraphLock);
    return r;
}
