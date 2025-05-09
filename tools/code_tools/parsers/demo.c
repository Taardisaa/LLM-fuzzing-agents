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