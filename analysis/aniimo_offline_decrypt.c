#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifndef MAP_JIT
#define MAP_JIT 0x800
#endif

typedef uint64_t (*core_fn_t)(const uint64_t *ctx, uint8_t *out, uint64_t len);

struct sample {
    const char *name;
    const char *path;
    size_t plain_len;
};

static const struct sample samples[] = {
    {"bool_prefix","blob_bool_prefix.bin",18},
    {"bool_mid","blob_bool_mid.bin",3},
    {"bool_true","blob_bool_true.bin",4},
    {"bool_false","blob_bool_false.bin",5},
    {"bool_suffix","blob_bool_suffix.bin",17},
    {"float_prefix","blob_float_prefix.bin",18},
    {"float_mid","blob_float_mid.bin",3},
    {"float_suffix","blob_float_suffix.bin",17},
};

static size_t align8(size_t x) { return (x + 7u) & ~7u; }

static uint8_t *read_file(const char *path, size_t *size_out) {
    FILE *f=fopen(path,"rb");
    if(!f){perror(path); return NULL;}
    fseek(f,0,SEEK_END); long n=ftell(f); rewind(f);
    if(n<=0){fclose(f); return NULL;}
    uint8_t *p=(uint8_t*)malloc((size_t)n);
    if(!p){fclose(f); return NULL;}
    if(fread(p,1,(size_t)n,f)!=(size_t)n){free(p); fclose(f); return NULL;}
    fclose(f); *size_out=(size_t)n; return p;
}

int main(void) {
#if !defined(__aarch64__) && !defined(__arm64__)
    fprintf(stderr,"requires arm64 host\n");
    return 2;
#endif
    size_t core_size=0,sigma_size=0;
    uint8_t *core_bytes=read_file("core.bin",&core_size);
    uint8_t *sigma=read_file("sigma.bin",&sigma_size);
    if(!core_bytes||!sigma||sigma_size!=16) return 3;

    const size_t map_size=0x450000;
    uint8_t *base=(uint8_t*)mmap(NULL,map_size,PROT_READ|PROT_WRITE,
                                 MAP_PRIVATE|MAP_ANON|MAP_JIT,-1,0);
    if(base==MAP_FAILED){perror("mmap"); return 4;}

    memcpy(base+0x4000,core_bytes,core_size);
    memcpy(base+0x389000,sigma,16);

    static uint64_t fake_guard=0x1122334455667788ULL;
    *(uintptr_t *)(base+0x440000)=(uintptr_t)&fake_guard;

    __builtin___clear_cache((char *)(base+0x4000),(char *)(base+0x4000+core_size));
    if(mprotect(base,map_size,PROT_READ|PROT_EXEC)!=0){perror("mprotect"); return 5;}

    core_fn_t core=(core_fn_t)(void *)(base+0x4000);

    for(size_t i=0;i<sizeof(samples)/sizeof(samples[0]);++i){
        const struct sample *s=&samples[i];
        size_t blob_size=0;
        uint8_t *blob=read_file(s->path,&blob_size);
        if(!blob) return 6;

        size_t n=s->plain_len;
        size_t off_nonce=n;
        size_t off_key=off_nonce+12;
        size_t off_seed=off_key+32;
        size_t off_state=off_seed+8;
        size_t off_len=align8(off_state+16);
        if(off_len+8>blob_size){fprintf(stderr,"%s malformed\n",s->name); return 7;}

        uint64_t stored_len=0;
        memcpy(&stored_len,blob+off_len,8);

        uint64_t ctx[6]={
            (uint64_t)(uintptr_t)blob,
            (uint64_t)(uintptr_t)(blob+off_nonce),
            (uint64_t)(uintptr_t)(blob+off_key),
            (uint64_t)(uintptr_t)(blob+off_seed),
            (uint64_t)(uintptr_t)(blob+off_state),
            stored_len
        };

        uint8_t out[256]={0};
        uint64_t ret=core(ctx,out,n);
        out[n]=0;

        printf("%s|len=%zu|stored=%llu|ret=%llu|hex=",s->name,n,
               (unsigned long long)stored_len,(unsigned long long)ret);
        for(size_t j=0;j<n;++j) printf("%02x",out[j]);
        printf("|text=");
        for(size_t j=0;j<n;++j){
            unsigned c=out[j];
            if(c>=0x20&&c<=0x7e) putchar((int)c);
            else printf("\\x%02x",c);
        }
        putchar('\n');
        free(blob);
    }
    return 0;
}
