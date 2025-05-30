#include <stdbool.h>
#include "dns/types.h"


#define ISC_LEXCOMMENT_DNSMASTERFILE 0x08

enum dns_decompress {
        DNS_DECOMPRESS_DEFAULT,
        DNS_DECOMPRESS_PERMITTED,
        DNS_DECOMPRESS_NEVER,
        DNS_DECOMPRESS_ALWAYS,
};


static inline dns_decompress_t /* inline to suppress code generation */
dns_decompress_setpermitted(dns_decompress_t dctx, bool permitted) {
        if (dctx == DNS_DECOMPRESS_NEVER || dctx == DNS_DECOMPRESS_ALWAYS) {
                return dctx;
        } else if (permitted) {
                return DNS_DECOMPRESS_PERMITTED;
        } else {
                return DNS_DECOMPRESS_DEFAULT;
        }
}

IGRAPH_EXPORT igraph_error_t igraph_read_graph_pajek(igraph_t *graph, FILE *instream){

}
LLAMA_API int32_t llama_vocab_n_tokens(const struct llama_vocab * vocab);
LIBBPF_API struct bpf_object *
bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
                     const struct bpf_object_open_opts *opts);


LLAMA_API uint32_t llama_model_quantize(
    const char * fname_inp,
    const char * fname_out,
    const llama_model_quantize_params * params);
            

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        isc_buffer_t buf;
        isc_result_t result;

        isc_buffer_constinit(&buf, data, size);
        isc_buffer_add(&buf, size);
        isc_buffer_setactive(&buf, size);

        CHECK(isc_lex_openbuffer(lex, &buf));

        do {
                isc_token_t token;
                result = isc_lex_gettoken(lex, 0, &token);
        } while (result == ISC_R_SUCCESS);

        return 0;
}


// struct_specifier_query
struct dns_zone {
	/* Unlocked */
	unsigned int magic;
	isc_mutex_t lock;
#ifdef DNS_ZONE_CHECKLOCK
	bool locked;
#endif /* ifdef DNS_ZONE_CHECKLOCK */
	isc_mem_t *mctx;
	isc_refcount_t references;

	isc_rwlock_t dblock;
	dns_db_t *db; /* Locked by dblock */

	unsigned int tid;
        dns_zone_t *master;       
	/* Locked */
	dns_zonemgr_t *zmgr;
	ISC_LINK(dns_zone_t) link; /* Used by zmgr. */
	isc_loop_t *loop;
}

// struct_specifier_query
typedef struct A {
        bool is_valid;
} B;

// type definnition
typedef struct dns_name	 dns_name_t;
typedef unsigned int uint32_t;

// template 
template <typename T>
T myMax(T x, T y) {
  return (x > y) ? x : y;
}


