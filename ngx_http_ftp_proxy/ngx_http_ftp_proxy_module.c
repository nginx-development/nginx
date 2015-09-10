/*
 * =============================================================================
 *
 *       Filename:  ngx_http_ftp_proxy_module.c
 *    Description:  http ftp proxy module
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
#include <ngx_http_appframe.h>

#include <ngx_http_proxy_switch.h>

#define NGX_FTP_PROXY_MAX_RESOURCE_NUM	128

#define SIZEOF_ARRAY(array) (sizeof((array))/sizeof((array)[0]))

enum {
	NGX_FTP_CTRL_NONE = 0,
	NGX_FTP_DATA_NONE = 0,
	NGX_FTP_DATA_BEGIN = 1,
	NGX_FTP_CTRL_WAIT_DATA_REQ,
	NGX_FTP_DATA_REQ_WAIT,
	NGX_FTP_DATA_DONE,
};

typedef struct {
	ngx_uint_t		cmd_state;
	ngx_uint_t		response_state;
	ngx_int_t		response_code;
	ngx_int_t		multi_line_flag;
	u_char			response_code_string[3];

	u_char			*cmd_start;
	u_char			*cmd_end;
	u_char			*cmd_arg_start;
	u_char			*cmd_arg_end;

	u_char			*response_start;
	u_char			*response_end;
	u_char			*response_code_start;
	u_char			*response_code_end;
	u_char			*response_multi_line_start;
	u_char			*response_multi_line_last_line;
	u_char			*response_multi_line_end;
	u_char			*response_arg_start;
	u_char			*response_arg_end;
}ngx_ftp_package_t;

enum{
	NGX_FTP_TYPE_NONE = 0,
	NGX_FTP_CONTROL_CONNECTION,
	NGX_FTP_DATA_CONNECTION
};

typedef struct {
	ngx_int_t				ref;
	ngx_queue_t				ports;
	ngx_slab_pool_t			*shpool;
}ngx_http_ftp_DC_cache_t;

typedef struct {
	ngx_queue_t	qnode;
	ngx_uint_t	port;
	void		*data;
	ngx_http_ftp_DC_cache_t	*DC_cache;
}ngx_http_ftp_DC_data_t;

typedef struct {
	u_char					color;
	ngx_str_t				name;
	ngx_shm_t				shm;
	ngx_http_ftp_DC_cache_t	cache;
	u_char					end;
}ngx_http_ftp_proxy_cache_node_t;

typedef struct {
	ngx_shm_zone_t			*shm_zone;
	ngx_http_ftp_DC_cache_t	*cache;
	ngx_str_t				name;
}ngx_http_ftp_DC_cache_ctx_t;

typedef struct {
	ngx_shm_zone_t		*shm_zone;
	ngx_rbtree_t		*rbtree;
}ngx_http_ftp_proxy_main_cache_ctx_t;

typedef struct {
	u_char 		name[5];
	ngx_uint_t	deny;
}cmd_struct_t;

typedef struct {
	ngx_queue_t		head;
	ngx_uint_t		num;
}ngx_http_ftp_proxy_connections_t;

typedef struct {
	ngx_shm_zone_t						*shm_zone;
	ngx_http_ftp_proxy_connections_t 	*connections;
}ngx_http_ftp_proxy_connection_pool_ctx_t;

typedef struct {
	ngx_queue_t		qnode;
	ngx_atomic_t	ref;
	ngx_uint_t		ctrl_status;
	ngx_uint_t		data_status;
	ngx_http_ftp_proxy_connection_pool_ctx_t *connpool_ctx;
}ngx_http_ftp_proxy_connection_t;

typedef struct {
	ngx_uint_t				type;		//0:control tunnel; 1: data tunnel.
	ngx_ftp_package_t		package;
	ngx_http_ftp_proxy_connection_t			 *connection;
	ngx_http_ftp_DC_data_t	*DC_data;
	ngx_http_cleanup_pt		*connection_cleanup;
	ngx_http_cleanup_pt		*cache_cleanup;
}ngx_http_ftp_proxy_ctx_t;

typedef struct {
	ngx_uint_t				  					state;
	ngx_uint_t									shm_index;	//use different shm for different server config.
    ngx_http_upstream_conf_t   					upstream;
	ngx_array_t				 					*proxy_lengths;
	ngx_array_t				  					*proxy_values;
	ngx_http_ftp_DC_cache_ctx_t   				*DC_cache_ctx;
	ngx_http_ftp_proxy_connection_pool_ctx_t	*connpool_ctx;
	ngx_http_ftp_proxy_main_cache_ctx_t			*main_cache;
	ngx_rbtree_node_t							*node;
} ngx_http_ftp_proxy_loc_conf_t;

typedef struct {
	ngx_http_ftp_proxy_main_cache_ctx_t				*main_cache;
	ngx_http_ftp_proxy_connection_pool_ctx_t		*connpool_ctx;
	ngx_uint_t										DC_cache_size;
	ngx_uint_t										cache_size;
	ngx_uint_t										connection_pool_size;
}ngx_http_ftp_proxy_main_conf_t;

static char *
ngx_http_ftp_proxy_main_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *
ngx_http_ftp_proxy_create_main_conf(ngx_conf_t *cf);
static char *
ngx_http_ftp_proxy_init_main_conf(ngx_conf_t *cf, void *conf);

static ngx_rbtree_node_t *
ngx_http_ftp_proxy_cache_lookup(ngx_rbtree_t *rbtree, ngx_str_t *vv,
    uint32_t hash);

static ngx_int_t
ngx_http_ftp_proxy_conf_handler(ngx_conf_t *cf, ngx_http_dyconfig_t *dyconfig);
static ngx_int_t
ngx_http_ftp_proxy_handler(ngx_http_request_t *r);

static ngx_int_t
ngx_http_ftp_proxy_create_established_response(ngx_http_request_t *r);
static ngx_int_t ngx_http_ftp_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ftp_proxy_reinit_request(ngx_http_request_t *r);
static void ngx_http_ftp_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_ftp_proxy_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);
static ngx_int_t
ngx_http_ftp_proxy_upstream_process_header(ngx_http_request_t *r);
static ngx_int_t
ngx_http_ftp_proxy_upstream_protoparse_filter(void *data, ssize_t bytes);
ngx_int_t
ngx_http_ftp_parse_cmd_line(ngx_http_request_t *r, 
		ngx_ftp_package_t *ftp, ngx_buf_t *b);

static ngx_int_t
ngx_http_ftp_proxy_input_filter_init(void *data);

static ngx_int_t
ngx_http_ftp_proxy_downstream_process_header(ngx_http_request_t *r, 
		ngx_http_downstream_t *d);
static ngx_int_t
ngx_http_ftp_proxy_downstream_protoparse_filter(void *data, ssize_t bytes);
ngx_int_t
ngx_http_ftp_parse_response_line(ngx_http_request_t *r, 
		ngx_ftp_package_t *ftp, ngx_buf_t *b);

static ngx_int_t
get_num(u_char **str, char ch);
#if 0
static char *
ngx_http_ftp_proxy_DC_cache(ngx_conf_t *cf, 
		ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_ftp_proxy_protoparse_cache_init_zone(ngx_shm_zone_t *shm_zone, 
		void *data);
#endif
static ngx_int_t
ngx_http_ftp_proxy_protoparse_init(ngx_conf_t *cf);

static void
ngx_http_ftp_proxy_dyconfig_cleanup(void *data);

static char *
ngx_http_ftp_proxy_connection_pool_cache(ngx_conf_t *cf, 
		ngx_command_t *cmd, void *conf);
static void 
ngx_http_ftp_proxy_connection_cleanup(void *data);

static void
ngx_http_ftp_DC_data_destroy_locked(ngx_http_ftp_DC_data_t *data);

static void
ngx_http_ftp_DC_data_destroy(ngx_http_ftp_DC_data_t *data);

static ngx_int_t
ngx_http_ftp_DC_check_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_ftp_proxy_check_data_connection(ngx_http_request_t	*r,
		ngx_http_ftp_DC_cache_ctx_t *cache_ctx);
#if 0
static ngx_int_t
ngx_http_ftp_del_DC_data_from_cache(ngx_http_ftp_DC_cache_t *cache, 
		ngx_uint_t port, ngx_http_ftp_DC_data_t *data);
#endif
static ngx_int_t
ngx_http_ftp_get_DC_data_from_cache(ngx_http_ftp_DC_cache_t *cache, 
		ngx_uint_t port, ngx_http_ftp_DC_data_t *data);

static void *ngx_http_ftp_proxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ftp_proxy_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_ftp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static cmd_struct_t cmd_array[] = {	/*Pinched in part SUSE */
	{"PORT", 1},	/*proxy suite! */
	{"PASV", 0},
	{"ABOR", 0},
	{"USER", 0},
	{"PASS", 0},
	{"ACCT", 0},
	{"CWD",  0},
	{"CDUP", 0},
	{"SMNT", 0},
	{"QUIT", 0},
	{"REIN", 0},
	{"TYPE", 0},
	{"STRU", 0},
	{"MODE", 0},
	{"RETR", 0},
	{"STOR", 0},
	{"STOU", 0},
	{"APPE", 0},
	{"ALLO", 0},
	{"REST", 0},
	{"RNFR", 0},
	{"RNTO", 0},
	{"DELE", 0},
	{"RMD",  0},
	{"MKD",  0},
	{"PWD",  0},
	{"LIST", 0},
	{"NLST", 0},
	{"SITE", 0},
	{"SYST", 0},
	{"STAT", 0},
	{"HELP", 0},
	{"NOOP", 0},
	{"SIZE", 0},	/* Not found in RFC 959 */
	{"MDTM", 0},
	{"MLSD", 0},
	{"MLFL", 0},
	{"MAIL", 0},
	{"MSND", 0},
	{"MSOM", 0},
	{"MSAM", 0},
	{"MRSQ", 0},
	{"MRCP", 0},
	{"XCWD", 0},
	{"XMKD", 0},
	{"XRMD", 0},
	{"XPWD", 0},
	{"XCUP", 0},
	{"FEAT", 0},
#if 0
	{"APSV", 0},	/* As per RFC 1579      */
#endif
	{"", 0}
};

static ngx_http_handler_pt ngx_http_upstream_next_check_filter;

static ngx_command_t  ngx_http_ftp_proxy_commands[] = {

    { ngx_string("ftp_proxy_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_ANY,
      ngx_http_ftp_proxy_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
 
	{ ngx_string("ftp_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ftp_proxy_loc_conf_t, upstream.timeout),
      NULL },

    { ngx_string("ftp_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ftp_proxy_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("ftp_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ftp_proxy_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("ftp_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ftp_proxy_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("ftp_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ftp_proxy_loc_conf_t, upstream.read_timeout),
      NULL },
		
	{ ngx_string("ftp_connection_pool"),
	  NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
	  ngx_http_ftp_proxy_connection_pool_cache,
	  0,
	  0,
	  NULL },

#if 0
	{ ngx_string("ftp_DC_cache"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_http_ftp_proxy_DC_cache,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },
#endif

	{ ngx_string("ftp_main_cache"),
	  NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
	  ngx_http_ftp_proxy_main_cache,
	  0,
	  0,
	  NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ftp_proxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_ftp_proxy_protoparse_init,    /* postconfiguration */

    ngx_http_ftp_proxy_create_main_conf,   /* create main configuration */
    ngx_http_ftp_proxy_init_main_conf,     /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ftp_proxy_create_loc_conf,    /* create location configuration */
    ngx_http_ftp_proxy_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_ftp_proxy_module = {
    NGX_MODULE_V1,
    &ngx_http_ftp_proxy_module_ctx,        /* module context */
    ngx_http_ftp_proxy_commands,           /* module directives */
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

static ngx_http_dyconfig_module_t ngx_http_ftp_proxy_dyconfig_module = {
	&ngx_http_ftp_proxy_module,
	ngx_http_ftp_proxy_conf_handler
};

static ngx_http_proxy_instance_t ngx_http_ftp_proxy= {
	ngx_string("ftp_proxy"),
	ngx_http_ftp_proxy_handler,
	&ngx_http_ftp_proxy_dyconfig_module
};

static ngx_int_t
ngx_http_ftp_proxy_conf_handler(ngx_conf_t *cf, ngx_http_dyconfig_t *dyconfig)
{
	uint32_t							hash;
	ngx_shm_t							*shm = NULL;
	ngx_shm_zone_t						*shm_zone = NULL;
	ngx_rbtree_node_t					*node = NULL;
	ngx_slab_pool_t						*shpool = NULL, *sp = NULL;
	ngx_http_ftp_proxy_loc_conf_t		*flcf = NULL;
	ngx_http_ftp_DC_cache_t				*cache = NULL;
	ngx_http_ftp_DC_cache_ctx_t			*cache_ctx = NULL;
	ngx_http_ftp_proxy_main_cache_ctx_t	*ctx = NULL;
	ngx_http_ftp_proxy_cache_node_t		*lc = NULL;
	ngx_http_ftp_proxy_main_conf_t		*fmcf = NULL;
	ngx_http_cleanup_t					*cln = NULL;

	fmcf = ngx_http_dyconfig_get_module_main_conf(dyconfig, ngx_http_ftp_proxy_module);
	if (fmcf == NULL || fmcf->main_cache == NGX_CONF_UNSET_PTR){
		ngx_log_error(NGX_LOG_WARN, dyconfig->log, 0,
				"dyconfig get fmcf is not configured");
		return NGX_OK;
	}

	flcf = ngx_http_dyconfig_get_module_loc_conf(dyconfig, ngx_http_ftp_proxy_module);
	if (flcf == NULL || flcf->DC_cache_ctx != NGX_CONF_UNSET_PTR){
		ngx_log_error(NGX_LOG_ERR, dyconfig->log, 0,
				"dyconfig conf: %s.", flcf == NULL ? "flcf is null":"DC cache ctx is duplicated");
		return NGX_ERROR;
	}

	cache_ctx = ngx_palloc(cf->pool, sizeof(ngx_http_ftp_DC_cache_ctx_t));
	if (cache_ctx == NULL){
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
				"cache ctx palloc error");
		return NGX_ERROR;
	}

	cache_ctx->cache = NULL;
	cache_ctx->shm_zone = fmcf->main_cache->shm_zone;
	cache_ctx->name = dyconfig->name;

	flcf->DC_cache_ctx = cache_ctx;

	//get cache by mapid
	ctx = fmcf->main_cache;
	shm_zone = ctx->shm_zone;

	hash = ngx_crc32_short(dyconfig->name.data, dyconfig->name.len);

	shpool = (ngx_slab_pool_t *) ctx->shm_zone->shm.addr;

	ngx_shmtx_lock(&shpool->mutex);

	node = ngx_http_ftp_proxy_cache_lookup(ctx->rbtree, &dyconfig->name, hash);

	if (node == NULL) {

		node = ngx_slab_alloc_locked(shpool, 
				sizeof(ngx_http_ftp_proxy_cache_node_t) + 
				fmcf->DC_cache_size + 
				sizeof(ngx_rbtree_node_t));

		if (node == NULL) {
			ngx_shmtx_unlock(&shpool->mutex);
			//TODO: destroy
			return NGX_ERROR;
		}

		lc = (ngx_http_ftp_proxy_cache_node_t *) &node->color;

		node->key = hash;
		lc->name.data = ngx_slab_alloc_locked(shpool, dyconfig->name.len + 1);
		if (lc->name.data == NULL){
			ngx_shmtx_unlock(&shpool->mutex);
			return NGX_ERROR;
		}

		ngx_memcpy(lc->name.data, dyconfig->name.data, dyconfig->name.len);
		lc->name.len = dyconfig->name.len;
		shm = &lc->shm;
		
		shm->addr = (u_char *)lc + sizeof(ngx_http_ftp_proxy_cache_node_t) + sizeof(ngx_shm_t);
		shm->size = fmcf->DC_cache_size - sizeof(ngx_shm_t);
		shm->log = dyconfig->log;
		shm->name = lc->name;
		shm->exists = 1;

		sp = (ngx_slab_pool_t *)shm->addr;
		sp->end = shm->addr + shm->size;
		sp->min_shift = 3;
		sp->addr = shm->addr;

		if (ngx_shmtx_create(&sp->mutex, 
					&sp->lock, NULL) != NGX_OK){
			ngx_shmtx_unlock(&shpool->mutex);
			return NGX_ERROR;
		}

		ngx_slab_init(sp);

#if 0
		chshpool = &lc->shpool;

		if (ngx_shmtx_create(&chshpool->mutex, 
					&chshpool->lock, NULL) != NGX_OK){
			ngx_shmtx_unlock(&shpool->mutex);
			return NGX_ERROR;
		}
		
		chshpool->start = (u_char *)&lc->cache;
		chshpool->end = (u_char *)node + fmcf->DC_cache_size;
		cache = &lc->cache;
		cache->ref = 0;

		//TODO: calc cache info
		chshpool->data = cache;

		start =(u_char *)chshpool->data + sizeof(ngx_http_ftp_DC_cache_t);
		end = (u_char *)chshpool->end;

		max = (end - start) / sizeof(ngx_http_ftp_DC_data_t);

		if (max < 1){
			return NGX_ERROR;
		}

		cache->start = start;
		cache->max = max;
		cache->end = end;
		cache->cur = 0;
		cache->shpool = shpool;

		ngx_log_error(NGX_LOG_DEBUG, shm_zone->shm.log, 0,
				"ftp DC shm cache(%V):%p\nmax:%d.\nstart:%p.\nend:%p.\ncur:%d.\narray:%p.\n",
				&cache_ctx->name, cache, cache->max, 
				cache->start, cache->end, cache->cur, cache->array);
#endif
		ngx_rbtree_insert(ctx->rbtree, node);

		cache = &lc->cache;

		cache->ref = 0;
		cache->shpool = sp;
		ngx_queue_init(&cache->ports);

		cache_ctx->cache = cache; //shm data
	} else {

		lc = (ngx_http_ftp_proxy_cache_node_t *) &node->color;
		cache = &lc->cache;
	}

	cache->ref++;

	ngx_shmtx_unlock(&shpool->mutex);

	flcf->DC_cache_ctx->cache = cache;
	flcf->node = node;
	flcf->main_cache = fmcf->main_cache;

	cln = ngx_http_dyconfig_cleanup_add(dyconfig, 0);
	if (cln == NULL ){
		return NGX_ERROR;
	}

	cln->handler = ngx_http_ftp_proxy_dyconfig_cleanup;
	cln->data = flcf;

	flcf->connpool_ctx = fmcf->connpool_ctx;

	return NGX_OK;
}

//connection pool used for record ftp ctrl & data connection statues.

static ngx_http_ftp_proxy_connection_t *
ngx_http_ftp_proxy_connection_create(ngx_http_ftp_proxy_connection_pool_ctx_t *connpool_ctx)
{
	ngx_slab_pool_t				*shpool = NULL;
	ngx_http_ftp_proxy_connection_t	*conn = NULL;

    shpool = (ngx_slab_pool_t *) connpool_ctx->shm_zone->shm.addr;

	ngx_shmtx_lock(&shpool->mutex);
    conn = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_ftp_proxy_connection_t));
    if (conn == NULL) {
		ngx_shmtx_unlock(&shpool->mutex);
        return NULL;
    }

	//ngx_memzero(conn, sizeof(ngx_http_ftp_proxy_connection_t));
	ngx_queue_insert_head(&connpool_ctx->connections->head, &conn->qnode);
	ngx_shmtx_unlock(&shpool->mutex);

	conn->connpool_ctx = connpool_ctx;
	conn->ctrl_status = NGX_FTP_CTRL_NONE;
	conn->data_status = NGX_FTP_DATA_NONE;

	return conn;
}

static ngx_int_t
ngx_http_ftp_proxy_connection_get(ngx_http_ftp_proxy_connection_t *conn)
{

	ngx_atomic_fetch_add(&conn->ref, 1);
	
	return NGX_OK;
}

static ngx_int_t
ngx_http_ftp_proxy_connection_put(ngx_http_ftp_proxy_connection_t *conn)
{
	ngx_atomic_t		ref = 0;
	ngx_slab_pool_t		*shpool = NULL;

	ref = ngx_atomic_fetch_add(&conn->ref, -1);

	if (ref != 0){
		return NGX_OK;
	}

    shpool = (ngx_slab_pool_t *) conn->connpool_ctx->shm_zone->shm.addr;

	ngx_shmtx_lock(&shpool->mutex);

	ngx_queue_remove(&conn->qnode);
    ngx_slab_free_locked(shpool, conn);

	ngx_shmtx_unlock(&shpool->mutex);

	return NGX_OK;
}

static void
ngx_http_ftp_proxy_dyconfig_cleanup(void *data)
{
	ngx_http_ftp_proxy_loc_conf_t	*flcf = data;
	ngx_slab_pool_t					*shpool = NULL;

	shpool = (ngx_slab_pool_t *) flcf->main_cache->shm_zone->shm.addr;

	ngx_shmtx_lock(&shpool->mutex);

	flcf->DC_cache_ctx->cache->ref--;
	if (flcf->DC_cache_ctx->cache->ref == 0){
		ngx_rbtree_delete(flcf->main_cache->rbtree, flcf->node);
		ngx_slab_free((ngx_slab_pool_t *)flcf->main_cache->shm_zone->shm.addr,
				flcf->node);
	}

	ngx_shmtx_unlock(&shpool->mutex);

	return;
}

static ngx_rbtree_node_t *
ngx_http_ftp_proxy_cache_lookup(ngx_rbtree_t *rbtree, ngx_str_t *vv,
    uint32_t hash)
{
    ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_ftp_proxy_cache_node_t  *fpcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        fpcn = (ngx_http_ftp_proxy_cache_node_t *) &node->color;

        rc = ngx_memn2cmp(vv->data, fpcn->name.data,
                          (size_t) vv->len, (size_t) fpcn->name.len);
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

#if 0
static void
ngx_http_ftp_proxy_cache_cleanup(void *data)
{
    ngx_http_limit_conn_cleanup_t  *lccln = data;

    ngx_slab_pool_t             *shpool;
    ngx_rbtree_node_t           *node;
    ngx_http_limit_conn_ctx_t   *ctx;
    ngx_http_limit_conn_node_t  *lc;

    ctx = lccln->shm_zone->data;
    shpool = (ngx_slab_pool_t *) lccln->shm_zone->shm.addr;
    node = lccln->node;
    lc = (ngx_http_limit_conn_node_t *) &node->color;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, lccln->shm_zone->shm.log, 0,
                   "limit conn cleanup: %08XD %d", node->key, lc->conn);

    lc->conn--;

    if (lc->conn == 0) {
        ngx_rbtree_delete(ctx->rbtree, node);
        ngx_slab_free_locked(shpool, node);
    }

    ngx_shmtx_unlock(&shpool->mutex);
}
#endif

static void
ngx_http_ftp_proxy_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_http_ftp_proxy_cache_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (ngx_http_ftp_proxy_cache_node_t *) &node->color;
            lcnt = (ngx_http_ftp_proxy_cache_node_t *) &temp->color;

            p = (ngx_memn2cmp(lcn->name.data, lcnt->name.data, 
						lcn->name.len, lcnt->name.len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static char *
ngx_http_ftp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

	ngx_uint_t				   			n = 0;
    ngx_str_t                 			*value = NULL, *url = NULL;
	ngx_str_t				   			upstream_name;
    ngx_url_t                  			u;
	ngx_http_script_compile_t	   		sc;
    ngx_http_ftp_proxy_loc_conf_t 		*flcf = conf;

    if (flcf->upstream.upstream || flcf->proxy_lengths) {
        return "is duplicate";
    }

	if (cf->args->nelts > 2){
		return "input param format wrong";
	}

	ngx_str_set(&upstream_name, "tcp");
	if (ngx_http_proxy_switch_set_upstream_instance(cf, 
			&flcf->upstream, &upstream_name) != NGX_OK){

		return "upstream not support";
	}

	if (cf->args->nelts == 1){

		if (!ngx_http_conf_dyconfig_enabled(cf)){
			return "dyconfig not configured yet.";
		}

		if(ngx_http_proxy_switch_set_proxy_instance(cf, 
					&ngx_http_ftp_proxy) != NGX_OK){

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
		sc.lengths = &flcf->proxy_lengths;
		sc.values = &flcf->proxy_values;
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

		flcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
		if (flcf->upstream.upstream == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	if(ngx_http_proxy_switch_set_proxy_instance(cf, 
			&ngx_http_ftp_proxy) != NGX_OK){
		
		return NGX_CONF_ERROR;
	}

    return NGX_CONF_OK;
}

#if 0
static char *
ngx_http_ftp_proxy_DC_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ssize_t 			size = 0;
	u_char 				*p = NULL;
	ngx_str_t 			name = ngx_null_string;
	ngx_str_t 			s = ngx_null_string, namebuf = ngx_null_string;
	ngx_str_t 			*value = NULL;
	ngx_uint_t 			i = 0;
	ngx_shm_zone_t		*shm_zone = NULL;
	ngx_http_ftp_DC_cache_ctx_t 	*cache_ctx = NULL;
	ngx_http_ftp_proxy_loc_conf_t 		*flcf = conf;
	
	static	ngx_int_t	shm_index = 0;

    if (flcf->DC_cache_ctx != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

	value = cf->args->elts;

	for (i = 1; i < cf->args->nelts; i++) {
		if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
		
			name.data = value[i].data + 5;
		
			p = (u_char*)ngx_strchr(name.data, ':');
			if (NULL == p) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
						"invalid zone size \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			name.len = p - name.data;

			s.data = p + 1;
			s.len = value[i].data + value[i].len - s.data;

			size = ngx_parse_size(&s);
			if (NGX_ERROR == size) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
						"invalid zone size \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			if (size < (ssize_t)(1024 * ngx_pagesize)) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
						"zone \"%V\" is too small", &value[i]);
				return NGX_CONF_ERROR;
			}

			continue;
		}
	}
	
	if (0 == name.len) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
				"\"%V\" must have \"zone\" parameter", &cmd->name);
		return NGX_CONF_ERROR;
	}

	cache_ctx = ngx_palloc(cf->pool, sizeof(ngx_http_ftp_DC_cache_ctx_t));
	if (cache_ctx == NULL){
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
				"\"%V\" cache ctx palloc error", &cmd->name);
		return NGX_CONF_ERROR;
	}
	cache_ctx->cache = NULL;

	namebuf.data = ngx_pcalloc(cf->pool, name.len + 4);
	name.data[name.len] = '\0';
	ngx_snprintf(namebuf.data, name.len + 4, "%d:%s", shm_index , name.data);
	namebuf.len = ngx_strlen(namebuf.data);
	
	flcf->shm_index = shm_index;
	shm_index ++;

	shm_zone = ngx_shared_memory_add(cf, &namebuf, size,
										&ngx_http_ftp_proxy_module);
	if (NULL == shm_zone) {
		return NGX_CONF_ERROR;
	}

	if (shm_zone->data != NULL) {
		cache_ctx = shm_zone->data;
		return "shm zone have data.";
	}

	shm_zone->init = ngx_http_ftp_proxy_protoparse_cache_init_zone;
	shm_zone->data = cache_ctx;
	cache_ctx->shm_zone = shm_zone;
	cache_ctx->name = namebuf;

	flcf->DC_cache_ctx = cache_ctx;

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ftp_proxy_protoparse_cache_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
	ngx_http_ftp_DC_cache_ctx_t *ocache_ctx = data;
	ngx_http_ftp_DC_cache_ctx_t *cache_ctx = NULL;
	ngx_http_ftp_DC_cache_t 	*cache = NULL;
	ngx_slab_pool_t				*shpool = NULL;
	ngx_uint_t					max = 0;
	u_char 						*start = NULL, *end = NULL;

	cache_ctx = shm_zone->data;
	if (ocache_ctx) {
		cache_ctx->shm_zone = shm_zone;
		cache_ctx->cache = ocache_ctx->cache;
		return NGX_OK;
	}

	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

	if (shm_zone->shm.exists) {
		cache = shpool->data;
		return NGX_OK;
	}

	//slab init will destroy old data: 
	cache = (ngx_http_ftp_DC_cache_t *)shpool->start; 

	shpool->data = cache;

	start =(u_char *)shpool->data + sizeof(ngx_http_ftp_DC_cache_t);
	end = (u_char *)shpool->end;

	max = (end - start) / sizeof(ngx_http_ftp_DC_data_t);

	if (max < 1){
		return NGX_ERROR;
	}

	cache->start = start;
	cache->max = max;
	cache->end = end;
	cache->cur = 0;
	cache->shpool = shpool;

	ngx_log_error(NGX_LOG_DEBUG, shm_zone->shm.log, 0,
		"ftp DC shm cache(%V):%p\nmax:%d.\nstart:%p.\nend:%p.\ncur:%d.\narray:%p.\n",
		&cache_ctx->name, cache, cache->max, 
		cache->start, cache->end, cache->cur, cache->array);

	cache_ctx->cache = cache;

	return NGX_OK;
}
#endif

static ngx_int_t
ngx_http_ftp_proxy_protoparse_init(ngx_conf_t *cf)
{

	ngx_http_upstream_next_check_filter = ngx_http_upstream_check_filter;
	ngx_http_upstream_check_filter = ngx_http_ftp_DC_check_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ftp_DC_check_handler(ngx_http_request_t *r)
{
	ngx_int_t						rc = 0, type = 0;
	ngx_http_ftp_proxy_ctx_t		*ctx = NULL;
    ngx_http_ftp_proxy_loc_conf_t   *flcf = NULL;
	ngx_http_dyconfig_t				*dyconfig = NULL;
	ngx_access_t 					*access = NULL;
	ngx_resource_group_t 			*group = NULL;
	ngx_resource_t					*rsc = NULL;
	ngx_resource_member_t 			*member = NULL;
	ngx_uint_t						i = 0, nelts = 0;
	ngx_port_range_t				*elts = NULL;
	ngx_queue_t						*q = NULL;
	ngx_int_t						port = 0;


	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
			"ftp DC check handler");

	if (!(r->method & (NGX_HTTP_CONNECT))){
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
				"skip none cs server request");
		goto next;
	}

	if (ngx_http_dyconfig_enabled(r)){

		dyconfig = ngx_http_dyconfig_get_cur(r);
		if (dyconfig == NULL){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"dyconfig get cur error");
			goto err;
		}

		flcf = ngx_http_dyconfig_get_module_loc_conf(dyconfig, 
				ngx_http_ftp_proxy_module);
		if (flcf == NULL) {
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
					"flcf is not in the dyconfig");
			goto next;
		}

	}else{

		flcf = ngx_http_get_module_loc_conf(r, ngx_http_ftp_proxy_module);
		if (flcf == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
					"flcf is null error");
			goto err;
		}
	}

	if (flcf->DC_cache_ctx == NGX_CONF_UNSET_PTR) {
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
				"ftp DC cache not configured.");
		goto next;
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_ftp_proxy_module);
	if(ctx == NULL){
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
				"ftp proxy ctx not set yet error");
		goto next;
	}

#if 0	
	if (ctx->type == NGX_FTP_DATA_CONNECTION){
    	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                 "http ftp proxy connection is data connection.");
		goto ok;
	}
#endif
	access = ngx_http_request_access_curr(r);

	if (NULL == access) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"request access curr error.");
		goto err;
	}

	switch(access->type){
		case NGX_RESOURCE_TYPE_GROUP:
			group = ngx_http_request_group_curr(r);
			if (group == NULL){
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"user match get resource error.");
				goto err;
			}

			if (ngx_queue_empty(&group->member_queue)){
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"user match get resource group member is empty.");
				goto err;
			}

			q = ngx_queue_head(&group->member_queue);
			member = ngx_queue_data(q, ngx_resource_member_t, group_member_qnode);

			rsc = member->rsc;
			if (rsc == NULL){
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"user match get resource error.");
				goto err;
			}

			break;
		default:
			rsc = ngx_http_request_resource_curr(r);
			if (rsc == NULL){
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"user match get resource error.");
				goto err;
			}
			break;
	}

	switch(rsc->type){
		case NGX_RESOURCE_TYPE_TCPUDP:
			switch(rsc->proto){
				case NGX_RESOURCE_PROTO_FTP:
					break;
				default:
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
						"ftp proxy Unkown proto.");
					goto err;
			}
			nelts = NGX_SETOF_NELTS(rsc->tcpudp_ports);
			elts = NGX_SETOF_ELTS(rsc->tcpudp_ports);
			break;
		default:
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
					"ftp proxy Unkown type.");
			goto err;
	}

	port = ngx_atoi(r->connect_port_start, 
			r->connect_port_end - r->connect_port_start);

	if (port == NGX_ERROR){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"connect port request port parse error");
		goto err;
	}

	for (i = 0; i < nelts; i ++){
		if((port >= elts[i].start) && (port <= elts[i].end)){

			ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
					"ftp control connection.");
			type = NGX_FTP_CONTROL_CONNECTION;
			goto ok;
		}
	}

	rc = ngx_http_ftp_proxy_check_data_connection(r, flcf->DC_cache_ctx);
	if(rc == NGX_OK){
    	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                 "http ftp proxy data connection check.");
		type = NGX_FTP_DATA_CONNECTION;
		goto ok;
	}
	
	return NGX_ERROR;

next:	
	if (ngx_http_upstream_next_check_filter){
		return ngx_http_upstream_next_check_filter(r);
	}

	return NGX_OK;
ok:	
	ctx->type = type;
   	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"http ftp proxy %s connection.\
			(NOTICE: skip other upstream check)", 
			type == NGX_FTP_CONTROL_CONNECTION ? "ctrl" :"data");
	return NGX_OK;
err:
	return NGX_ERROR;
}

static ngx_int_t
ngx_http_ftp_proxy_check_data_connection(ngx_http_request_t	*r, 
		ngx_http_ftp_DC_cache_ctx_t *cache_ctx)
{	
	ngx_int_t						rc = 0, port = 0;
	ngx_http_ftp_DC_data_t   		data;
	ngx_http_ftp_proxy_ctx_t		*ctx = NULL;
	ngx_http_cleanup_t				*cln = NULL;

	port = ngx_atoi(r->connect_port_start, 
			r->connect_port_end - r->connect_port_start);
	
	if (port == NGX_ERROR){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"ftp proxy check connection port parse error");
		return NGX_ERROR;
	}

#if 0	
	cache = cache_ctx->cache;
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"ftp DC shm cache(%V):%p\nmax:%d.\nstart:%p.\nend:%p.\ncur:%d.\narray:%p.\n",
			&cache_ctx->name, cache, cache->max, 
			cache->start, cache->end, cache->cur, cache->array);
#endif

	ctx = ngx_http_get_module_ctx(r, ngx_http_ftp_proxy_module);

	rc = ngx_http_ftp_get_DC_data_from_cache(cache_ctx->cache, port, &data);
	if (rc != NGX_OK){
		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
				"ftp proxy check connection is not a data connection");
		return NGX_ERROR;
	}
	ctx->DC_data = NULL;

	ctx->connection = data.data;
	ctx->connection->data_status = NGX_FTP_DATA_BEGIN;

	ngx_http_ftp_proxy_connection_get(ctx->connection);

	if (ctx->connection_cleanup){
		cln = ngx_http_cleanup_add(r, 0);
		if (cln == NULL){
			return NGX_ERROR;
		}

		cln->handler = ngx_http_ftp_proxy_connection_cleanup;
		cln->data = ctx;
		ctx->connection_cleanup = &cln->handler;
	}

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
			"ftp proxy check connection is a data connection");
	return NGX_OK;
}

static void 
ngx_http_ftp_proxy_connection_cleanup(void *data)
{
	ngx_http_ftp_proxy_ctx_t 		*ctx = NULL;

	ctx = (ngx_http_ftp_proxy_ctx_t *)data;

	if (ctx->connection != NULL){
		ngx_http_ftp_proxy_connection_put(ctx->connection);
	}

	return;
}

static ngx_int_t
ngx_http_ftp_get_DC_data_from_cache(ngx_http_ftp_DC_cache_t *cache, 
		ngx_uint_t port, ngx_http_ftp_DC_data_t *data)
{
	ngx_queue_t		*q = NULL;
	ngx_http_ftp_DC_data_t	*d = NULL;

	ngx_shmtx_lock(&cache->shpool->mutex);
	for(q = ngx_queue_head(&cache->ports);
			q != ngx_queue_sentinel(&cache->ports);
			q = ngx_queue_next(q)){
		
		d = ngx_queue_data(q, ngx_http_ftp_DC_data_t, qnode);
		if (d->port	== port){
			*data = *d;
			//ngx_http_ftp_DC_data_destroy_locked(d);

			ngx_shmtx_unlock(&cache->shpool->mutex);
			return NGX_OK;
		}
	}

	ngx_shmtx_unlock(&cache->shpool->mutex);

	return NGX_ERROR;
}

#if 0
static ngx_int_t
ngx_http_ftp_del_DC_data_from_cache(ngx_http_ftp_DC_cache_t *cache, 
		ngx_uint_t port, ngx_http_ftp_DC_data_t *data)
{
	ngx_queue_t		*q = NULL;
	ngx_http_ftp_DC_data_t	*d = NULL;

	printf("cache ports:%p next:%p.\n",&cache->ports, cache->ports.next);
	ngx_shmtx_lock(&cache->shpool->mutex);
	for(q = ngx_queue_head(&cache->ports);
			q != ngx_queue_sentinel(&cache->ports);
			q = ngx_queue_next(q)){
		
		printf("q->prev:%p,q->next:%p.\n",q->prev,q->next);
		d = ngx_queue_data(q, ngx_http_ftp_DC_data_t, qnode);
		printf("q->prev:%p,q->next:%p.\n",q->prev,q->next);
		if (d->port	== port){
		printf("q->prev:%p,q->next:%p.\n",q->prev,q->next);
			*data = *d;
		printf("q->prev:%p,q->next:%p.\n",q->prev,q->next);
			ngx_http_ftp_DC_data_destroy_locked(d);

			ngx_shmtx_unlock(&cache->shpool->mutex);
			return NGX_OK;
		}
	}

	ngx_shmtx_unlock(&cache->shpool->mutex);

	return NGX_ERROR;
}
#endif

static ngx_http_ftp_DC_data_t *
ngx_http_ftp_add_DC_data_to_cache(ngx_http_ftp_DC_cache_t *cache, 
		ngx_http_ftp_DC_data_t data)
{
	ngx_http_ftp_DC_data_t *d = NULL;

	ngx_shmtx_lock(&cache->shpool->mutex);

	d = ngx_slab_alloc_locked(cache->shpool, sizeof(ngx_http_ftp_DC_data_t));
	if (d == NULL){
		ngx_shmtx_unlock(&cache->shpool->mutex);
		return NULL;
	}

	*d = data;
	ngx_queue_insert_head(&cache->ports, &d->qnode);

	ngx_shmtx_unlock(&cache->shpool->mutex);

	d->DC_cache = cache;

	return d;
}

static void 
ngx_http_ftp_DC_data_cleanup(void *data)
{	
	ngx_http_ftp_proxy_ctx_t	*ctx = NULL;

	ctx = (ngx_http_ftp_proxy_ctx_t *)data;

	if (ctx->DC_data != NULL){
		ngx_http_ftp_DC_data_destroy(ctx->DC_data);
		ctx->DC_data = NULL;
	}

	return;
}

static void
ngx_http_ftp_DC_data_destroy_locked(ngx_http_ftp_DC_data_t *data)
{
	ngx_queue_remove(&data->qnode);
	ngx_slab_free_locked(data->DC_cache->shpool, data);
}

static void
ngx_http_ftp_DC_data_destroy(ngx_http_ftp_DC_data_t *data)
{
	ngx_shmtx_lock(&data->DC_cache->shpool->mutex);

	ngx_http_ftp_DC_data_destroy_locked(data);

	ngx_shmtx_unlock(&data->DC_cache->shpool->mutex);
}

static ngx_int_t
ngx_http_ftp_proxy_process_timeout(ngx_http_request_t *r)
{
	ngx_http_ftp_proxy_ctx_t	*ctx = NULL;

	ctx = ngx_http_get_module_ctx(r, ngx_http_ftp_proxy_module);
	if(ctx == NULL){
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp proxy get module ctx is null");
		return NGX_ERROR;
	}

	if (ctx->type == NGX_FTP_CONTROL_CONNECTION
			&& ctx->connection != NULL){

		if (ctx->connection->data_status == NGX_FTP_DATA_BEGIN){

			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"http ftp proxy data connection processing");
			return NGX_BUSY;
		}

		if (ctx->connection->data_status == NGX_FTP_DATA_DONE){

			ctx->connection->data_status = NGX_FTP_DATA_NONE;
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"http ftp proxy data connection processing");
			return NGX_AGAIN;
		}
	}

	return NGX_DONE;
}

static ngx_int_t
ngx_http_ftp_proxy_handler(ngx_http_request_t *r)
{
    ngx_http_upstream_t            *u = NULL;
	ngx_http_downstream_t		   *d = NULL;	
	ngx_http_ftp_proxy_ctx_t	   *ctx = NULL;
    ngx_http_ftp_proxy_loc_conf_t  *flcf = NULL;

    if (!(r->method & (NGX_HTTP_CONNECT))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_ftp_proxy_module);

    u = r->upstream;

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ftp_proxy_ctx_t));
	if(ctx == NULL){
		return NGX_ERROR;
	}
	
	ctx->type = NGX_FTP_TYPE_NONE;

	ngx_http_set_ctx(r, ctx, ngx_http_ftp_proxy_module);

	if (ngx_http_dyconfig_enabled(r)){

		if(ngx_http_proxy_switch_set_upstream_srv_conf(r, u) != NGX_OK){

			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}else{

		if (ngx_http_proxy_switch_eval(r, 
					flcf->proxy_lengths, flcf->proxy_values) != NGX_OK){

			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	u->output.tag = (ngx_buf_tag_t) &ngx_http_ftp_proxy_module;

	u->conf = &flcf->upstream;

	u->create_established_response = ngx_http_ftp_proxy_create_established_response;
	u->process_timeout = ngx_http_ftp_proxy_process_timeout;
	u->create_request = ngx_http_ftp_proxy_create_request;
	u->reinit_request = ngx_http_ftp_proxy_reinit_request;
	u->process_header = ngx_http_ftp_proxy_upstream_process_header;
	u->abort_request = ngx_http_ftp_proxy_abort_request;
	u->finalize_request = ngx_http_ftp_proxy_finalize_request;
	r->state = 0;
	
	u->input_filter_init = ngx_http_ftp_proxy_input_filter_init;
	u->input_filter = ngx_http_ftp_proxy_upstream_protoparse_filter;
	u->input_filter_ctx = r;

	if( ngx_http_downstream_create(r,u) != NGX_OK){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	d = u->downstream;

    d->output.tag = (ngx_buf_tag_t) &ngx_http_ftp_proxy_module;

	d->process_timeout = ngx_http_ftp_proxy_process_timeout;
	d->process_header = ngx_http_ftp_proxy_downstream_process_header;
	
	d->input_filter_init = ngx_http_ftp_proxy_input_filter_init;
	d->input_filter = ngx_http_ftp_proxy_downstream_protoparse_filter;
	d->input_filter_ctx = r;

	return ngx_http_proxy_switch_start(r);
}


//NOTICE: check connection type.
static ngx_int_t
ngx_http_ftp_proxy_upstream_protoparse_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

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

static ngx_int_t
ngx_http_ftp_proxy_input_filter_init(void *data)
{
    ngx_http_request_t   *r = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ftp proxy input filter init");

    return NGX_OK;
}

static ngx_int_t
ngx_http_ftp_proxy_downstream_protoparse_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

	ngx_uint_t			  		i = 0;
    ngx_buf_t            		*b = NULL;
    ngx_chain_t          		*cl = NULL, **ll = NULL;
	ngx_ftp_package_t 			*ftp = NULL;
    ngx_http_upstream_t  		*u = NULL;
	ngx_http_downstream_t		*d = NULL;
	ngx_http_ftp_proxy_ctx_t	*ctx = NULL;

    u = r->upstream;
	d = u->downstream;
    b = &d->buffer;
	
	ctx = ngx_http_get_module_ctx(r, ngx_http_ftp_proxy_module);
	if(ctx == NULL){
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp proxy get module ctx is null");
		goto err;
	}

	if (ctx->type == NGX_FTP_DATA_CONNECTION){
    	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                   "http ftp proxy data connection");
		goto find;
	}

	ftp = &ctx->package;

	//client protocal filter 
	for(i = 0; i < SIZEOF_ARRAY(cmd_array); i++ ){
		if (ngx_strncasecmp(cmd_array[i].name, 
					ftp->cmd_start, ngx_strlen(cmd_array[i].name)) == 0){
			if ( cmd_array[i].deny){
    			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                		   "http ftp proto(%s) forbidden.", cmd_array[i].name);
				goto err;
			}
#if 0
			rc = cmd_array[i].cmd(ctx);
#endif
    		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                   "http ftp proxy cmd connection command found.");
			goto find;
		}
	}
    		
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
    	"http ftp proxy cmd connection command not found.");

	goto err;

find:	

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

	cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = d->output.tag;

    return NGX_OK;

err:

	return NGX_ERROR;
}


static ngx_int_t
ngx_http_ftp_proxy_downstream_process_header(ngx_http_request_t *r, 
		ngx_http_downstream_t *d)
{
	ngx_int_t					rc = 0;
	ngx_buf_t					*b = NULL;
	ngx_http_upstream_t			*u = NULL;
	ngx_http_ftp_proxy_ctx_t	*ctx = NULL;

	u = r->upstream;
	b = &d->buffer;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, d->connection->log, 0,
                   "http ftp proxy downstream process header");

	ctx = ngx_http_get_module_ctx(r, ngx_http_ftp_proxy_module);
	if(ctx == NULL){

    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp proxy get module ctx is null");
		return NGX_ERROR;
	}

	if (ctx->type == NGX_FTP_DATA_CONNECTION){
    	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                   "http ftp proxy data connection");
		return NGX_OK;
	}

	rc = ngx_http_ftp_parse_cmd_line(r, &ctx->package, b);
	if(rc == NGX_ERROR){
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp proto parse error");
		return NGX_ERROR;
	}

	if(rc == NGX_AGAIN){
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp control connection line not finished yet.");
		return NGX_AGAIN;
	}

	return NGX_OK;
}

ngx_int_t
ngx_http_ftp_parse_cmd_line(ngx_http_request_t *r, 
		ngx_ftp_package_t *ftp, ngx_buf_t *b)
{
	u_char 			ch, *p = NULL;
	static u_char	*pos = NULL;

	enum {
		sw_start = 0,
		sw_cmd,
		sw_arg_start,
		sw_arg,
		sw_almost_done,
	}state;

	state = ftp->cmd_state;

	if (state != sw_start){
		p = pos;
	}else{
		p = b->pos;
	}

	for( ; p < b->last; p++){
		ch = *p;
		switch(state){
			case sw_start:
				ftp->cmd_start = b->pos;
				state = sw_cmd;
				break;
			case sw_cmd:
				ftp->cmd_end = p;
				if( ch == ' '){
					state = sw_arg_start;
					break;
				}

				if( ch == CR ){
					state = sw_almost_done;
					break;
				}

				if( ch == LF ){
					goto done;
				}

				break;
			case sw_arg_start:
				ftp->cmd_arg_start = p;
				state = sw_arg;
				break;

			case sw_arg:
				ftp->cmd_arg_end = p;
				if ( ch == CR ){
					state = sw_almost_done;
					break;
				}

				if( ch == LF ){
					goto done;
				}

				break;
			case sw_almost_done:
				if (ch == LF){
					goto done;
				}
				return NGX_ERROR;
		}
	}

	pos = p;
	ftp->cmd_state = state;
	return NGX_AGAIN;

done:

	ftp->cmd_state = sw_start;
	return NGX_OK;
}


	static ngx_int_t
ngx_http_ftp_proxy_create_established_response(ngx_http_request_t *r)
{

	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.status_line,"200 Connection established");
	r->headers_out.content_length_n = 0;
	r->header_only = 1;

	return NGX_OK;
}



static ngx_int_t
ngx_http_ftp_proxy_create_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ftp proxy create request");

	return NGX_OK;
}

static ngx_int_t
ngx_http_ftp_proxy_reinit_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ftp proxy reinit request");
    return NGX_OK;
}

static ngx_int_t
get_num(u_char **str, char ch)
{
	char 	*_p = NULL;
	u_char	*tmp = NULL;

	if (str == NULL || *str == NULL){
		return NGX_ERROR;
	}

	tmp = *str;
 	_p = ngx_strchr((char *)tmp, ch); 
 	if (_p == NULL){
		return NGX_ERROR;
	}
	*str = (u_char *)_p + 1;
	return ngx_atoi(tmp, (u_char *) _p - tmp);
}

static ngx_int_t
ngx_http_ftp_proxy_upstream_process_header(ngx_http_request_t *r)
{
	ngx_int_t					rc = 0;
	ngx_buf_t					*b = NULL;
	u_char						*tmp = NULL;
	ngx_int_t					a1 = 0,a2 = 0,a3 = 0,a4 = 0, p1 = 0, p2 = 0;
	ngx_uint_t					port = 0;
	ngx_http_upstream_t			*u = NULL;
	ngx_http_ftp_proxy_ctx_t	*ctx = NULL;
	ngx_http_dyconfig_t			*dyconfig = NULL;
	ngx_ftp_package_t			*ftp = NULL;
	ngx_http_ftp_DC_data_t		data;
    ngx_http_ftp_proxy_loc_conf_t  	*flcf = NULL;
	ngx_http_ftp_proxy_connection_t		*conn = NULL;
	ngx_http_cleanup_t					*cln = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ftp proxy upstream process header");

	u = r->upstream;
	b = &u->buffer;

	ctx = ngx_http_get_module_ctx(r, ngx_http_ftp_proxy_module);
	if(ctx == NULL){

    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp proxy get module ctx is null");
		return NGX_ERROR;
	}

	if (ctx->type == NGX_FTP_DATA_CONNECTION){
    	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                   "http ftp proxy data connection");
		return NGX_OK;
	}

	if (ngx_http_dyconfig_enabled(r)){

		dyconfig = ngx_http_dyconfig_get_cur(r);
		if (dyconfig == NULL){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"dyconfig get cur error");
			return NGX_ERROR;
		}

		flcf = ngx_http_dyconfig_get_module_loc_conf(dyconfig, 
				ngx_http_ftp_proxy_module);
		if (flcf == NULL) {
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
					"flcf is not in the dyconfig");
			return NGX_ERROR;
		}

	}else{

		flcf = ngx_http_get_module_loc_conf(r, ngx_http_ftp_proxy_module);

		if (flcf == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"http ftp flcf is null");
			return NGX_ERROR;
		}
	}

	ftp = &ctx->package;

	rc = ngx_http_ftp_parse_response_line(r, ftp, b);
	if(rc == NGX_ERROR){
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp proxy protoparse response line error");
		return NGX_ERROR;
	}

	if(rc == NGX_AGAIN){
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp control connection line not finished yet.");
		return NGX_AGAIN;
	}
	
	if (flcf->DC_cache_ctx == NGX_CONF_UNSET_PTR){
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp proxy DC cache not configured.");
		return NGX_OK;
	}

	if (ftp->response_code == 227){
		//PASV mode parse ip & port.
		tmp = (u_char *)ngx_strcasestrn(ftp->response_arg_start, 
				"Entering Passive Mode (", 22);
		if (tmp == NULL){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"http ftp proxy pasv response(%s) parse error.", ftp->response_arg_start);
			return NGX_ERROR;
		}

		tmp = tmp + 23;
		
		a1 = get_num(&tmp,',');
		if (a1 < 0){
			return NGX_ERROR;
		}
		a2 = get_num(&tmp,',');
		if (a2 < 0){
			return NGX_ERROR;
		}
		a3 = get_num(&tmp,',');
		if (a3 < 0){
			return NGX_ERROR;
		}
		a4 = get_num(&tmp,',');
		if (a4 < 0){
			return NGX_ERROR;
		}
		p1 = get_num(&tmp,',');
		if (p1 < 0){
			return NGX_ERROR;
		}
		p2 = get_num(&tmp,')');
		if (p2 < 0){
			return NGX_ERROR;
		}

		port = (p1 << 8) + (p2 & 0xFF) ;

		if (flcf->connpool_ctx == NGX_CONF_UNSET_PTR){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp proxy connection no config error.");
			return NGX_ERROR;
		}

		if (ctx->connection != NULL){
			ngx_http_ftp_proxy_connection_put(ctx->connection);
			ctx->connection = NULL;
		}

		conn = ngx_http_ftp_proxy_connection_create(flcf->connpool_ctx);
		if (conn == NULL){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp proxy connection get error.");
			return NGX_ERROR;
		}
		
		ngx_http_ftp_proxy_connection_get(conn);
		conn->ctrl_status = NGX_FTP_CTRL_WAIT_DATA_REQ;
		conn->data_status = NGX_FTP_DATA_REQ_WAIT;

		ngx_memzero(&data, sizeof(ngx_http_ftp_DC_data_t));
		data.port = port;
		data.data = conn;

		if (ctx->DC_data != NULL){
			ngx_http_ftp_DC_data_destroy(ctx->DC_data);
		}

		ctx->DC_data = 
			ngx_http_ftp_add_DC_data_to_cache(flcf->DC_cache_ctx->cache, data);

		if (ctx->DC_data == NULL){
    		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                   "http ftp proxy add PACS port to DC cache error.");
			ngx_http_ftp_proxy_connection_put(conn);
			ctx->connection = NULL;
			return NGX_ERROR;
		}

		if (ctx->cache_cleanup == NULL){
			cln = ngx_http_cleanup_add(r, 0);
			if (cln == NULL){
				return NGX_ERROR;
			}

			cln->handler = ngx_http_ftp_DC_data_cleanup;
			cln->data = ctx;

			ctx->cache_cleanup = &cln->handler;
		}

		ctx->connection = conn;
	}

	return NGX_OK;
}

ngx_int_t
ngx_http_ftp_parse_response_line(ngx_http_request_t *r, 
		ngx_ftp_package_t *ftp, ngx_buf_t *b)
{
	u_char 	ch,*p = NULL;
	static u_char	*pos = NULL;
	
	enum {
		sw_start = 0,
		sw_code_01,
		sw_code_02,
		sw_code_end,
		sw_delimiter,
		sw_arg_start,
		sw_arg,
		sw_almost_done,
		sw_multi_line_first,
		sw_multi_line_parse_head,
		sw_multi_line_parse,
	}state;

	state = ftp->response_state;
	if (state != sw_start){
		p = pos;
	}else{
		p = b->pos;
	}

	for( ; p < b->last; p++){
		ch = *p;

		switch(state){
			case sw_start:
				if ( ch == ' '){
					break;
				}
				
				if (ftp->multi_line_flag){
					state = sw_multi_line_parse_head;
					break;
				}

				ftp->response_code_start = b->pos;
				state = sw_code_01;
				break;
			case sw_code_01:
				if ( ch < '0' || ch > '9'){
					return NGX_ERROR;
				}
				state = sw_code_02;
				break;
			case sw_code_02:
				if ( ch < '0' || ch > '9'){
					return NGX_ERROR;
				}

				state = sw_code_end;
				break;
			case sw_code_end:
				ftp->response_code_end = p;
				ngx_memcpy(&ftp->response_code_string, ftp->response_code_start, 3);
				ftp->response_code = ngx_atoi(ftp->response_code_start, 
							ftp->response_code_end - ftp->response_code_start);

				if (ftp->response_code == NGX_ERROR){
 			   		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            		       "http ftp proxy parse cmd response code error.");
					return NGX_ERROR;
				}
				
				p -= 1;
				state = sw_delimiter;
				break;
			case sw_delimiter:
				ftp->response_code_end = p;
				if ( ch == ' '){
					state = sw_arg_start;
					break;
				}

				if ( ch == '-'){
					//multi-line
					ftp->multi_line_flag = 1;
					state = sw_multi_line_first;
					break;
				}

				return NGX_ERROR;

			case sw_multi_line_first:
				if ( ch == LF ){
					state = sw_multi_line_parse_head;
					break;
				}
				break;

			case sw_multi_line_parse_head:
				ftp->response_multi_line_last_line = p;
				state = sw_multi_line_parse;

				break;

			case sw_multi_line_parse:
				ftp->response_multi_line_end = p;

				if ( ch == LF ){
					if (ngx_strncmp(ftp->response_code_string, 
								ftp->response_multi_line_last_line, 3) == 0){

						ftp->response_end = p;
						ftp->multi_line_flag = 0;
						goto done;
					}

					state = sw_multi_line_parse_head;
					break;
				}
				
				break;

			case sw_arg_start:

				ftp->response_arg_start = p;
				state = sw_arg;
				break;

			case sw_arg:
				ftp->response_arg_end = p;
				if ( ch == CR ){
					ftp->response_end = p;
					state = sw_almost_done;
					break;
				}

				if (ch == LF){
					goto done;
				}

				break;
			case sw_almost_done:
				if (ch == LF){
					goto done;
				}
				return NGX_ERROR;
		}
	}

	pos = p;
	ftp->response_state = state;
	return NGX_AGAIN;

done:

	ftp->response_state = sw_start;
	return NGX_OK;
}

static void
ngx_http_ftp_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http ftp proxy request");
    return;
}


static void
ngx_http_ftp_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
	ngx_http_ftp_proxy_ctx_t		*ctx = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http ftp proxy request");

	ctx = ngx_http_get_module_ctx(r, ngx_http_ftp_proxy_module);

	if (ctx->connection != NULL){

		if (ctx->type == NGX_FTP_DATA_CONNECTION){
			ctx->connection->data_status = NGX_FTP_DATA_DONE;
		}
		ngx_http_ftp_proxy_connection_put(ctx->connection);
		ctx->connection = NULL;
	}

    return;
}

static void *
ngx_http_ftp_proxy_create_main_conf(ngx_conf_t *cf)
{
	ngx_http_ftp_proxy_main_conf_t	*fmcf = NULL;

	fmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ftp_proxy_main_conf_t));
	if (fmcf == NULL){
		return NULL;
	}

	fmcf->main_cache = NGX_CONF_UNSET_PTR;
	fmcf->connpool_ctx = NGX_CONF_UNSET_PTR;
	fmcf->DC_cache_size = NGX_CONF_UNSET_UINT;
	fmcf->cache_size = NGX_CONF_UNSET_UINT;

	return fmcf;
}

static char *
ngx_http_ftp_proxy_init_main_conf(ngx_conf_t *cf, void *conf)
{
#if 0
	ngx_http_ftp_proxy_main_conf_t	*fmcf = conf;

	fmcf->main_cache = NGX_CONF_UNSET_PTR;
	fmcf->shm_zone = NGX_CONF_UNSET_PTR;
	fmcf->DC_cache_size = NGX_CONF_UNSET_UINT;
	fmcf->cache_size = NGX_CONF_UNSET_UINT;
#endif
	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ftp_proxy_connection_pool_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                      len;
    ngx_slab_pool_t            *shpool;
    ngx_http_ftp_proxy_connection_pool_ctx_t  *ctx , *octx = data;

    ctx = shm_zone->data;

    if (octx) {

		ctx->shm_zone = shm_zone;
        ctx->connections = octx->connections;

        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->connections = (ngx_http_ftp_proxy_connections_t *)shpool->data;

        return NGX_OK;
    }

    ctx->connections = ngx_slab_alloc(shpool, sizeof(ngx_http_ftp_proxy_connections_t));
    if (ctx->connections == NULL) {
        return NGX_ERROR;
    }

    shpool->data = ctx->connections;

	ctx->connections->num = 0;
	ngx_queue_init(&ctx->connections->head);

    len = sizeof(" in ftp_proxy_connection_pool_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in ftp_proxy_connection_pool_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}

static char *
ngx_http_ftp_proxy_connection_pool_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
	u_char                     		*p;
    ssize_t                     	size = 0;
    ngx_str_t                  		*value, name, s;
    ngx_uint_t                  	i;
    ngx_shm_zone_t             		*shm_zone;
    ngx_http_ftp_proxy_connection_pool_ctx_t  *ctx;
	ngx_http_ftp_proxy_main_conf_t			*fmcf = conf;


    value = cf->args->elts;

    ctx = NULL;
    size = 0;
    name.len = 0;

	value = cf->args->elts;

	for (i = 1; i < cf->args->nelts; i++) {
		if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
		
			name.data = value[i].data + 5;
		
			p = (u_char*)ngx_strchr(name.data, ':');
			if (NULL == p) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
						"invalid zone size \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			name.len = p - name.data;

			s.data = p + 1;
			s.len = value[i].data + value[i].len - s.data;

			size = ngx_parse_size(&s);
			if (NGX_ERROR == size) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
						"invalid zone size \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			if (size < (ssize_t)(1024 * ngx_pagesize)) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
						"zone \"%V\" is too small", &value[i]);
				return NGX_CONF_ERROR;
			}

			continue;
		}
	}
	
    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_ftp_proxy_connection_pool_ctx_t));
	if (ctx == NULL){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ctx pcalloc error");
        return NGX_CONF_ERROR;
	}

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_ftp_proxy_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bounded",
                           &cmd->name, &name);
        return NGX_CONF_ERROR;
    }

	ctx->shm_zone = shm_zone;
	fmcf->connpool_ctx = ctx;
	fmcf->connection_pool_size = size;

    shm_zone->init = ngx_http_ftp_proxy_connection_pool_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ftp_proxy_main_cache_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                      len;
    ngx_slab_pool_t            *shpool;
    ngx_rbtree_node_t          *sentinel;
    ngx_http_ftp_proxy_main_cache_ctx_t  *ctx , *octx = data;

    ctx = shm_zone->data;

    if (octx) {
	
		ctx->shm_zone = shm_zone;
        ctx->rbtree = octx->rbtree;

        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;

        return NGX_OK;
    }

    ctx->rbtree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel,
                    ngx_http_ftp_proxy_rbtree_insert_value);

    len = sizeof(" in ftp_proxy_main_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in ftp_proxy_main_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}

static char *
ngx_http_ftp_proxy_main_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ 
	u_char                     		*p;
    ssize_t                     	size = 0, n = 0;
    ngx_str_t                  		*value, name, s;
    ngx_uint_t                  	i;
    ngx_shm_zone_t             		*shm_zone;
    ngx_http_ftp_proxy_main_cache_ctx_t  *ctx;
	ngx_http_ftp_proxy_main_conf_t			*fmcf = conf;


    value = cf->args->elts;

    ctx = NULL;
    size = 0;
    name.len = 0;

	value = cf->args->elts;

	for (i = 1; i < cf->args->nelts; i++) {
		if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
		
			name.data = value[i].data + 5;
		
			p = (u_char*)ngx_strchr(name.data, ':');
			if (NULL == p) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
						"invalid zone size \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			name.len = p - name.data;

			s.data = p + 1;
			s.len = value[i].data + value[i].len - s.data;

			size = ngx_parse_size(&s);
			if (NGX_ERROR == size) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
						"invalid zone size \"%V\"", &value[i]);
				return NGX_CONF_ERROR;
			}

			if (size < (ssize_t)(1024 * ngx_pagesize)) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
						"zone \"%V\" is too small", &value[i]);
				return NGX_CONF_ERROR;
			}

			continue;
		}
	}
	
    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_ftp_proxy_main_cache_ctx_t));
	if (ctx == NULL){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ctx pcalloc error");
        return NGX_CONF_ERROR;
	}

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_ftp_proxy_module);

    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bounded",
                           &cmd->name, &name);
        return NGX_CONF_ERROR;
    }

	ctx->shm_zone = shm_zone;
	fmcf->main_cache = ctx;
	fmcf->cache_size = size;

    shm_zone->init = ngx_http_ftp_proxy_main_cache_init_zone;
    shm_zone->data = ctx;

	//???? n 
	n = offsetof(ngx_rbtree_node_t, color)
                + offsetof(ngx_http_ftp_proxy_cache_node_t, cache)
                + 256; //name len

	if (size / n < NGX_FTP_PROXY_MAX_RESOURCE_NUM){
		return NGX_CONF_ERROR;
	}

	fmcf->DC_cache_size = size / NGX_FTP_PROXY_MAX_RESOURCE_NUM;

    return NGX_CONF_OK;
}

static void *
ngx_http_ftp_proxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ftp_proxy_loc_conf_t  *conf = NULL;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ftp_proxy_loc_conf_t));
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
	conf->DC_cache_ctx = NGX_CONF_UNSET_PTR;
	conf->connpool_ctx = NGX_CONF_UNSET_PTR;
	conf->main_cache = NGX_CONF_UNSET_PTR;
	conf->node = NGX_CONF_UNSET_PTR;
	conf->shm_index = 0;

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
ngx_http_ftp_proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ftp_proxy_loc_conf_t *prev = parent;
    ngx_http_ftp_proxy_loc_conf_t *conf = child;

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

