/*
 * =============================================================================
 *
 *       Filename:  ngx_http_udp_proxy_module.c
 *    Description:  http udp proxy module
 *
 *        Version:  1.0
 *        Created:  2013-12-16 11:24:39
 *       Revision:  none
 *         Author:  mayfengcrazy@163.com, 
 *        Company:  CUN
 *
 * =============================================================================
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_proxy_switch.h>


#define NGX_PROXY_DOWNSTREAM

typedef struct {
    ngx_http_upstream_conf_t   upstream;
	ngx_array_t				  *proxy_lengths;
	ngx_array_t				  *proxy_values;
} ngx_http_udp_proxy_loc_conf_t;

typedef struct { 
	uint8_t			ver;
	uint16_t		length;
}__attribute__((packed)) ngx_udp_header_t;

typedef struct {
	ngx_uint_t				type;		//0:control tunnel; 1: data tunnel.
	ngx_udp_header_t		udp_hdr;
}ngx_http_udp_proxy_ctx_t;


static ngx_int_t
ngx_http_udp_proxy_handler(ngx_http_request_t *r);

static ngx_int_t
ngx_http_udp_proxy_create_established_response(ngx_http_request_t *r);
static ngx_int_t ngx_http_udp_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_udp_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_udp_proxy_upstream_process_header(ngx_http_request_t *r);
static void ngx_http_udp_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_udp_proxy_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t
ngx_http_udp_proxy_downstream_filter(void *data, ssize_t bytes);
static ngx_int_t
ngx_http_udp_proxy_downstream_filter_init(void *data);

static void *ngx_http_udp_proxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_udp_proxy_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_udp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t
ngx_http_udp_proxy_upstream_input_filter_init(void *data);
static ngx_int_t
ngx_http_udp_proxy_upstream_non_buffered_copy_filter(void *data, ssize_t bytes);


#ifdef NGX_PROXY_DOWNSTREAM
static ngx_int_t
ngx_http_udp_proxy_downstream_process_header(ngx_http_request_t *r, 
		ngx_http_downstream_t *d);
#endif


static ngx_http_proxy_instance_t ngx_http_udp_proxy= {
	ngx_string("udp_proxy"),
	ngx_http_udp_proxy_handler,
	NULL,
};

static ngx_command_t  ngx_http_udp_proxy_commands[] = {

    { ngx_string("udp_proxy_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_ANY,
      ngx_http_udp_proxy_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
	{ ngx_string("udp_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_udp_proxy_loc_conf_t, upstream.timeout),
      NULL },

    { ngx_string("udp_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_udp_proxy_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("udp_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_udp_proxy_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("udp_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_udp_proxy_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("udp_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_udp_proxy_loc_conf_t, upstream.read_timeout),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_udp_proxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_udp_proxy_create_loc_conf,    /* create location configuration */
    ngx_http_udp_proxy_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_udp_proxy_module = {
    NGX_MODULE_V1,
    &ngx_http_udp_proxy_module_ctx,        /* module context */
    ngx_http_udp_proxy_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_udp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_uint_t				   			n = 0;
    ngx_str_t                 			*value = NULL, *url = NULL;
	ngx_str_t				   			upstream_name;
    ngx_url_t                  			u;
	ngx_http_script_compile_t	   		sc;
    ngx_http_udp_proxy_loc_conf_t 		*ulcf = conf;

    if (ulcf->upstream.upstream || ulcf->proxy_lengths) {
        return "is duplicate";
    }

	if (cf->args->nelts > 2){
		return "input param format wrong";
	}

	ngx_str_set(&upstream_name, "udp");
	if (ngx_http_proxy_switch_set_upstream_instance(cf, 
			&ulcf->upstream, &upstream_name) != NGX_OK){

		return "upstream not support";
	}

	if (cf->args->nelts == 1){

		if (!ngx_http_conf_dyconfig_enabled(cf)){
			return "dyconfig not configured yet.";
		}

		if(ngx_http_proxy_switch_set_proxy_instance(cf, 
					&ngx_http_udp_proxy) != NGX_OK){

			return NGX_CONF_ERROR;
		}
    	return NGX_CONF_OK;
	}

	value = cf->args->elts;
	url = &value[1];

	n = ngx_http_script_variables_count(url);

	if (n) {

		ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

		sc.cf = cf;
		sc.source = url;
		sc.lengths = &ulcf->proxy_lengths;
		sc.values = &ulcf->proxy_values;
		sc.variables = n;
		sc.complete_lengths = 1;
		sc.complete_values = 1;

		if (ngx_http_script_compile(&sc) != NGX_OK) {
			return NGX_CONF_ERROR;
		}

	}else{

		ngx_memzero(&u, sizeof(ngx_url_t));

		u.url = *url;
		u.no_resolve = 1;

		ulcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
		if (ulcf->upstream.upstream == NULL) {
			return NGX_CONF_ERROR;
		}

	}

	if(ngx_http_proxy_switch_set_proxy_instance(cf, 
			&ngx_http_udp_proxy) != NGX_OK){
		
		return NGX_CONF_ERROR;
	}

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_udp_proxy_handler(ngx_http_request_t *r)
{
    ngx_http_upstream_t            *u = NULL;
#ifdef NGX_PROXY_DOWNSTREAM
	ngx_http_downstream_t			*d = NULL;
#endif
    ngx_http_udp_proxy_loc_conf_t  *ulcf = NULL;
    ngx_http_udp_proxy_ctx_t  	   *ctx = NULL;

    if (!(r->method & (NGX_HTTP_CONNECT))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_udp_proxy_ctx_t));
	if(ctx == NULL){
		return NGX_ERROR;
	}
	
	ngx_memzero(ctx, sizeof(ngx_http_udp_proxy_ctx_t));

	ngx_http_set_ctx(r, ctx, ngx_http_udp_proxy_module);

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_udp_proxy_module);

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

	if (ngx_http_dyconfig_enabled(r)){

		if(ngx_http_proxy_switch_set_upstream_srv_conf(r, u) != NGX_OK){

			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

	}else{

		if (ngx_http_proxy_switch_eval(r, 
					ulcf->proxy_lengths, ulcf->proxy_values) != NGX_OK){
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

    u->output.tag = (ngx_buf_tag_t) &ngx_http_udp_proxy_module;

    u->conf = &ulcf->upstream;

	u->create_established_response = ngx_http_udp_proxy_create_established_response;
	u->create_request = ngx_http_udp_proxy_create_request;
	u->reinit_request = ngx_http_udp_proxy_reinit_request;
	u->process_header = ngx_http_udp_proxy_upstream_process_header;
	u->abort_request = ngx_http_udp_proxy_abort_request;
	u->finalize_request = ngx_http_udp_proxy_finalize_request;
	r->state = 0;
	
	u->input_filter_init = ngx_http_udp_proxy_upstream_input_filter_init;
	u->input_filter = ngx_http_udp_proxy_upstream_non_buffered_copy_filter;
	u->input_filter_ctx = r;
#ifdef NGX_PROXY_DOWNSTREAM
	if( ngx_http_downstream_create(r,u) != NGX_OK){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	d = u->downstream;

    d->output.tag = (ngx_buf_tag_t) &ngx_http_udp_proxy_module;

	d->process_header = ngx_http_udp_proxy_downstream_process_header;
	
	d->input_filter_init = ngx_http_udp_proxy_downstream_filter_init;
	d->input_filter = ngx_http_udp_proxy_downstream_filter;
	d->input_filter_ctx = r;
#endif
	return ngx_http_proxy_switch_start(r);
}

static ngx_int_t
ngx_http_udp_proxy_downstream_filter_init(void *data)
{
    ngx_http_request_t   *r = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http udp proxy input filter init");

    return NGX_OK;
}

static ngx_int_t
ngx_http_udp_proxy_upstream_input_filter_init(void *data)
{
    ngx_http_request_t   *r = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http udp proxy upstream filter init");

    return NGX_OK;
}

static ngx_int_t
ngx_http_udp_proxy_upstream_non_buffered_copy_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;
	ngx_udp_header_t	 *udp_hdr = NULL;

    u = r->upstream;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

	udp_hdr = ngx_palloc(r->pool, sizeof(ngx_udp_header_t));
	if(udp_hdr == NULL){
		return NGX_ERROR;
	}

    cl->buf->pos = (u_char *)udp_hdr;
    cl->buf->last = cl->buf->pos + sizeof(ngx_udp_header_t);
    cl->buf->tag = u->output.tag;
	
	udp_hdr->ver=0x01;
	udp_hdr->length=htons(bytes);


    ll = &cl->next;
    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    if (u->length == -1) {
        return NGX_OK;
    }

    u->length -= bytes;

    if (u->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NGX_OK;
}


#ifdef NGX_PROXY_DOWNSTREAM
static ngx_int_t
ngx_http_udp_proxy_downstream_process_header(ngx_http_request_t *r, 
		ngx_http_downstream_t *d)
{
	ngx_buf_t					*b = NULL;
	ngx_udp_header_t			*udp_hdr = NULL;
	ngx_http_upstream_t			*u = NULL;
	ngx_http_udp_proxy_ctx_t	*ctx = NULL;

	u = r->upstream;
	b = &d->buffer;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, d->connection->log, 0,
                   "http udp proxy downstream process header");

	ctx = ngx_http_get_module_ctx(r, ngx_http_udp_proxy_module);
	if(ctx == NULL){

    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http udp proxy get module ctx is null");
		return NGX_ERROR;
	}

	if ((b->last - b->pos) < (int)sizeof(ngx_udp_header_t)){
    	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                   "http udp proxy header not ready.");
		return NGX_AGAIN;
	}

	udp_hdr = &ctx->udp_hdr;

	udp_hdr->ver = ((ngx_udp_header_t *) b->pos)->ver;
	udp_hdr->length = ((ngx_udp_header_t *) b->pos)->length;

	udp_hdr->length = ntohs(udp_hdr->length);
	
   	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"http udp proxy header->length:%d.", (int)udp_hdr->length);

	if (udp_hdr->length != (b->last - b->pos - sizeof(ngx_udp_header_t))){
		return NGX_AGAIN;
	}

	return NGX_OK;
}
#endif

static ngx_int_t
ngx_http_udp_proxy_downstream_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    ngx_buf_t            		*b = NULL;
    ngx_chain_t          		*cl = NULL, **ll = NULL;
	ngx_udp_header_t 			*udp_hdr = NULL;
    ngx_http_upstream_t  		*u = NULL;
	ngx_http_downstream_t		*d = NULL;
	ngx_http_udp_proxy_ctx_t	*ctx = NULL;

    u = r->upstream;
	d = u->downstream;
    b = &d->buffer;
	
	ctx = ngx_http_get_module_ctx(r, ngx_http_udp_proxy_module);
	if(ctx == NULL){
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http udp proxy get module ctx is null");
		return NGX_ERROR;
	}

	udp_hdr = &ctx->udp_hdr;

    for (cl = d->out_bufs, ll = &d->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(r->pool, &d->free_bufs);
    if (cl == NULL) {
        goto err;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

	cl->buf->pos = b->last + sizeof(ngx_udp_header_t);
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = d->output.tag;

    return NGX_OK;

err:

	return NGX_ERROR;
}

static ngx_int_t
ngx_http_udp_proxy_create_established_response(ngx_http_request_t *r)
{

	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.status_line,"200 Connection established");
	r->headers_out.content_length_n = 0;
	r->header_only = 1;

	return NGX_OK;
}

static ngx_int_t
ngx_http_udp_proxy_create_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http udp proxy create request");

	return NGX_OK;
}

static ngx_int_t
ngx_http_udp_proxy_reinit_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http udp proxy reinit request");
    return NGX_OK;
}


static ngx_int_t
ngx_http_udp_proxy_upstream_process_header(ngx_http_request_t *r)
{

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http udp proxy process header");

	return NGX_OK;
}


static void
ngx_http_udp_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http udp proxy request");
    return;
}


static void
ngx_http_udp_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http udp proxy request");
    return;
}


static void *
ngx_http_udp_proxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_udp_proxy_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_udp_proxy_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     */

	conf->upstream.upstream = NULL;

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    return conf;
}


static char *
ngx_http_udp_proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_udp_proxy_loc_conf_t *prev = parent;
    ngx_http_udp_proxy_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_msec_value(conf->upstream.timeout,
                              prev->upstream.timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    return NGX_CONF_OK;
}

