/*
 * =============================================================================
 *
 *       Filename:  ngx_http_dyconfig_module.c
 *    Description:  dyconfig module
 *
 *        Version:  1.0
 *        Created:  2014-03-24 19:50:08
 *       Revision:  none
 *         Author:  mayfengcrazy@163.com, 
 *        Company:  CUN
 *
 * =============================================================================
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_dyconfig_module.h>

#define NGX_DYCONFIG_DEFAULT_TIMEOUT 3600	//sec
#define NGX_HTTP_DYCONFIG_DESTROYING_TIMEOUT_BASE_NUM 10

typedef struct {
	void 			*data;
	ngx_event_t		*read;
	ngx_event_t		*write;
	ngx_socket_t	fd;
}ngx_timer_data_t;


typedef struct {
	ngx_http_dyconfig_t		*dyconfig;
}ngx_http_dyconfig_ctx_t;

typedef struct {
	ngx_pool_t 					*pool;	//not use yet
	ngx_log_t					*log;
	ngx_uint_t					 max_dyconfig_num;
	ngx_queue_t					 dyconfigs;
	ngx_queue_t					 destroying_dyconfigs;
	ngx_queue_t					 free_dyconfigs;
	ngx_msec_t					 timeout;
}ngx_http_dyconfig_main_dyconfig_t;

typedef struct {
	ngx_flag_t				enabled;
	time_t					timeout;
	ngx_uint_t				max_dyconfig_num;
}ngx_http_dyconfig_main_conf_t;

typedef struct {
	ngx_flag_t				enabled;
}ngx_http_dyconfig_loc_conf_t;


static void *
ngx_http_dyconfig_create_loc_conf(ngx_conf_t *cf);
static void *
ngx_http_dyconfig_create_main_conf(ngx_conf_t *cf);
static char *
ngx_http_dyconfig_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t
ngx_http_dyconfig_init_module(ngx_cycle_t *cycle);

static ngx_http_dyconfig_t *
ngx_http_dyconfig_create(ngx_http_request_t *r, ngx_str_t *name);
static ngx_http_dyconfig_t*
ngx_http_dyconfig_find(ngx_str_t	*name);
static void
ngx_http_dyconfig_cleanup_handler(void *data);
static void
ngx_http_dyconfig_timeout_handler(ngx_event_t *ev);
static u_char *
ngx_http_dyconfig_log_error(ngx_log_t *log, u_char *buf, size_t	len);


static ngx_http_dyconfig_main_dyconfig_t ngx_http_dyconfig;

static ngx_command_t  ngx_http_dyconfig_commands[] = {
 
    { ngx_string("dyconfig_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_sec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
	  offsetof(ngx_http_dyconfig_main_conf_t, timeout),
      NULL },

    { ngx_string("dyconfig"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dyconfig_loc_conf_t, enabled),
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_dyconfig_module_ctx = {
    NULL,							       /* preconfiguration */
    NULL,								   /* postconfiguration */

    ngx_http_dyconfig_create_main_conf,	/* create main configuration */
	ngx_http_dyconfig_init_main_conf,	/* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_dyconfig_create_loc_conf,        /* create location configuration */
    NULL,							          /* merge location configuration */
};


ngx_module_t  ngx_http_dyconfig_module = {
    NGX_MODULE_V1,
    &ngx_http_dyconfig_module_ctx,            /* module context */
    ngx_http_dyconfig_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
	ngx_http_dyconfig_init_module,			/* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_dyconfig_init_module(ngx_cycle_t *cycle)
{

	ngx_http_dyconfig.log = cycle->log;

	ngx_http_dyconfig.pool = ngx_create_pool(
			64 * sizeof(ngx_http_dyconfig_t), 
			ngx_http_dyconfig.log);

	if (ngx_http_dyconfig.pool == NULL){
		return NGX_ERROR;
	}

	return NGX_OK;
}

static void *
ngx_http_dyconfig_create_main_conf(ngx_conf_t *cf)
{
	ngx_http_dyconfig_main_conf_t	*dmcf = NULL;

	dmcf = ngx_palloc(cf->pool, sizeof(ngx_http_dyconfig_main_conf_t));
	if(dmcf == NULL){
		return NULL;
	}

	dmcf->timeout = NGX_CONF_UNSET;
	dmcf->max_dyconfig_num = NGX_CONF_UNSET_UINT;

	ngx_http_dyconfig.pool = NGX_CONF_UNSET_PTR;
	ngx_http_dyconfig.log = NGX_CONF_UNSET_PTR;
	ngx_http_dyconfig.timeout = NGX_CONF_UNSET_MSEC;
	ngx_http_dyconfig.max_dyconfig_num = NGX_CONF_UNSET_UINT;

	ngx_queue_init(&ngx_http_dyconfig.dyconfigs);
	ngx_queue_init(&ngx_http_dyconfig.destroying_dyconfigs);
	ngx_queue_init(&ngx_http_dyconfig.free_dyconfigs);

	return dmcf;
}

static char *
ngx_http_dyconfig_init_main_conf(ngx_conf_t *cf, void *conf)
{
	ngx_http_dyconfig_main_conf_t	*dmcf = conf;

	if (dmcf->timeout == NGX_CONF_UNSET){

		ngx_http_dyconfig.timeout = NGX_DYCONFIG_DEFAULT_TIMEOUT * 1000;
	}else {

		ngx_http_dyconfig.timeout = dmcf->timeout * 1000; //sec2msec
	}

	return NGX_CONF_OK;
}

ngx_http_dyconfig_t *
ngx_http_dyconfig_get_cur(ngx_http_request_t *r)
{
	ngx_http_dyconfig_ctx_t		*ctx = NULL;

	ctx = ngx_http_get_module_ctx(r, ngx_http_dyconfig_module);
	if (ctx != NULL && ctx->dyconfig != NULL){

		return ctx->dyconfig;
	}

	return NULL;
}

ngx_http_dyconfig_t *
ngx_http_dyconfig_get(ngx_http_request_t *r, ngx_str_t *name, ngx_uint_t option)
{
	ngx_http_dyconfig_t			*dyconfig = NULL;
	ngx_http_dyconfig_ctx_t		*ctx = NULL;
	ngx_http_cleanup_t			*cln = NULL;

	if (name == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"dyconfig get dyconfig input param error");
		return NULL;
	}

	if (option & NGX_HTTP_DYCONFIG_CURR){
		ctx = ngx_http_get_module_ctx(r, ngx_http_dyconfig_module);
		if (ctx != NULL && ctx->dyconfig != NULL){

			return ctx->dyconfig;
		}
	}

	if (option & NGX_HTTP_DYCONFIG_FIND){
		dyconfig = ngx_http_dyconfig_find(name);
	}else{
		dyconfig = NULL;
	}

	if (dyconfig == NULL){

		dyconfig = ngx_http_dyconfig_create(r, name);
		if(dyconfig == NULL){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"dyconfig create error");

			return NULL;
		}

		dyconfig->ref++;
		dyconfig->times++;

	}else{

		dyconfig->log->action = "dyconfig increference";
		dyconfig->ref++;
		dyconfig->times++;

	}

	cln = ngx_http_cleanup_add(r, 0);
	if (cln == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"dyconfig cleanup add error");

		ngx_http_dyconfig_destroy(dyconfig);
		return NULL;
	}

	cln->handler = ngx_http_dyconfig_cleanup_handler;
	cln->data = dyconfig;

	ctx = ngx_palloc(r->pool, sizeof(ngx_http_dyconfig_ctx_t));
	if (ctx == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"dyconfig palloc error");

		ngx_http_dyconfig_destroy(dyconfig);
		return NULL;
	}

	ctx->dyconfig = dyconfig;

	ngx_http_set_ctx(r, ctx, ngx_http_dyconfig_module);

	return dyconfig;
}

static void
ngx_http_dyconfig_cleanup_handler(void *data)
{
	ngx_http_dyconfig_t *dyconfig = data;

	ngx_http_dyconfig_destroy(dyconfig);

	return;
}

static ngx_http_dyconfig_t*
ngx_http_dyconfig_find(ngx_str_t *name)
{
	ngx_queue_t 						*head = NULL, *q = NULL;
	ngx_http_dyconfig_t 				*dyconfig = NULL;

	head = &ngx_http_dyconfig.dyconfigs;

	//TODO: optimize suggestion dhash
	for(q = ngx_queue_head(head); 
			q != ngx_queue_sentinel(head); 
			q = ngx_queue_next(q)){
		
		dyconfig = ngx_queue_data(q, ngx_http_dyconfig_t, qnode);

		if(ngx_strncmp(dyconfig->name.data, name->data, name->len) == 0){

			return dyconfig;
		}
	}

	return NULL;
}

static ngx_http_dyconfig_t *
ngx_http_dyconfig_alloc()
{
	ngx_queue_t			*q = NULL, *head = NULL;
	ngx_http_dyconfig_t	*dyconfig = NULL;
		
	head = &ngx_http_dyconfig.free_dyconfigs;
	for(q = ngx_queue_head(head); 
			q != ngx_queue_sentinel(head); 
			q = ngx_queue_next(q)){
		
		ngx_queue_remove(q);
		dyconfig = ngx_queue_data(q, ngx_http_dyconfig_t, qnode);
		
		dyconfig->ref = 0;
		dyconfig->times = 0;
		dyconfig->destroyed = 0;

		return dyconfig;
	}

	dyconfig = ngx_pcalloc(ngx_http_dyconfig.pool, sizeof(ngx_http_dyconfig_t));
	if (dyconfig == NULL){
		return NULL;
	}

	return dyconfig;
}

static ngx_http_dyconfig_t *
ngx_http_dyconfig_create(ngx_http_request_t *r, ngx_str_t *name)
{
	ngx_log_t							*log = NULL;
	ngx_pool_t							*pool = NULL;
	ngx_timer_data_t					*timerdata = NULL;
	ngx_http_dyconfig_t 				*dyconfig = NULL;
	ngx_http_conf_ctx_t					*ctx = NULL;
	ngx_http_core_srv_conf_t			*cscf = NULL;

	ngx_log_error(NGX_LOG_DEBUG, ngx_http_dyconfig.log, 0, 
				"create dyconfig (%V)", name);

	dyconfig = ngx_http_dyconfig_alloc();
	if (dyconfig == NULL){
		ngx_log_error(NGX_LOG_DEBUG, ngx_http_dyconfig.log, 0, 
				"create dyconfig (%V) failed: no mem.", name);
		return NULL;
	}

	pool = ngx_create_pool(128, ngx_http_dyconfig.log);
	if (pool == NULL){
		ngx_log_error(NGX_LOG_ERR, ngx_http_dyconfig.log, 0, 
				"create pool mem full");
		return NULL;
	}

	log = ngx_palloc(pool, sizeof(ngx_log_t));
	if(log == NULL){
		ngx_log_error(NGX_LOG_ERR, ngx_http_dyconfig.log, 0, 
				"create dyconfig log mem full");
		ngx_destroy_pool(pool);
		return NULL;
	}
	
	*log = *ngx_http_dyconfig.log;
	log->connection = 0;
	log->data = dyconfig;
	log->handler = ngx_http_dyconfig_log_error;
	log->action = "create dyconfig";

	dyconfig->pool = pool;
	dyconfig->log = log;
	
	timerdata = ngx_palloc(pool, sizeof(ngx_timer_data_t));

	dyconfig->name.data = ngx_palloc(pool, name->len + 1);
	if (dyconfig->name.data == NULL){
		ngx_log_error(NGX_LOG_ERR, ngx_http_dyconfig.log, 0, 
				"dyconfig mem full");
		ngx_destroy_pool(pool);
		return NULL;
	}

	ngx_cpystrn(dyconfig->name.data, name->data, name->len + 1);
	dyconfig->name.len = name->len;

	cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

	dyconfig->original_ctx = (void *)cscf->ctx;

	ctx = ngx_pcalloc(dyconfig->pool, sizeof(ngx_http_conf_ctx_t));
	if (ctx == NULL) {
		ngx_log_error(NGX_LOG_ERR, ngx_http_dyconfig.log, 0, 
				"create ctx conf palloc failed.");
		return NULL;
	}


	ctx->main_conf = r->main_conf;	//NOTICE: DO NOT modify main config.

	/* srv_conf */
	ctx->srv_conf = ngx_pcalloc(dyconfig->pool, 
			sizeof(void *) * ngx_http_max_module);
	if (ctx->srv_conf == NULL) {
		ngx_log_error(NGX_LOG_ERR, ngx_http_dyconfig.log, 0, 
				"create srv conf palloc failed.");
		return NULL;
	}

	/* loc_conf */
	ctx->loc_conf = ngx_pcalloc(dyconfig->pool, 
			sizeof(void *) * ngx_http_max_module);
	if (ctx->loc_conf == NULL) {
		ngx_log_error(NGX_LOG_ERR, ngx_http_dyconfig.log, 0, 
				"create loc conf palloc failed.");
		return NULL;
	}

	dyconfig->ctx = (void **)ctx;

	dyconfig->data = NULL;
	dyconfig->cleanup = NULL;

    if (ngx_array_init(&dyconfig->modules, dyconfig->pool, 4,
                       sizeof(ngx_http_dyconfig_module_t *))
        != NGX_OK)
    {
		ngx_log_error(NGX_LOG_ERR, ngx_http_dyconfig.log, 0, 
				"dyconfig mem full");
		ngx_destroy_pool(pool);
        return NULL;
    }

	ngx_queue_insert_head(&ngx_http_dyconfig.dyconfigs, &dyconfig->qnode);

	timerdata->data = dyconfig;
	timerdata->fd = 0;	//not used yet.

	ngx_memzero(&dyconfig->timer, sizeof(ngx_event_t));
	dyconfig->timer.data = timerdata;
	dyconfig->timer.handler = ngx_http_dyconfig_timeout_handler;
	dyconfig->timer.log = dyconfig->log;
	dyconfig->timeout = ngx_http_dyconfig.timeout;


	ngx_add_timer(&dyconfig->timer, dyconfig->timeout);
	
	return dyconfig;
}

ngx_int_t
ngx_http_dyconfig_register_module(ngx_http_dyconfig_t *dyconfig, 
	ngx_http_dyconfig_module_t *module)
{
	ngx_http_dyconfig_module_t	**modulep = NULL;

	modulep = ngx_array_push(&dyconfig->modules);
    if (modulep == NULL) {
        return NGX_ERROR;
    }

	*modulep = module;
	return NGX_OK;
}

//register & init module
ngx_int_t
ngx_http_dyconfig_add_module(ngx_http_request_t *r, ngx_http_dyconfig_t *dyconfig, 
	ngx_http_dyconfig_module_t *dyconfig_module)
{
	ngx_int_t				rc = 0;
	char					*rv = NULL;
	ngx_conf_t				cf;
	ngx_http_conf_ctx_t		*ctx = NULL, *original_ctx = NULL;
	ngx_module_t			*ngx_module = NULL;
	ngx_http_module_t		*module = NULL;
	void 					*mconf = NULL;

	ngx_memzero(&cf,sizeof(ngx_conf_t));

	if (dyconfig_module == NULL){
		ngx_log_error(NGX_LOG_ERR, dyconfig->log, 0, 
				"dyconfig add module input params wrong");
		return NGX_ERROR;
	}

	ctx = (ngx_http_conf_ctx_t *)dyconfig->ctx;


	cf.log = dyconfig->log;
	cf.pool = dyconfig->pool;
	cf.ctx = dyconfig->ctx;

	rc = ngx_http_dyconfig_register_module(dyconfig, dyconfig_module);
	if(rc != NGX_OK){
		ngx_conf_log_error(NGX_LOG_ERR, &cf, 0, 
				"dyconfig register module failed.");
		return NGX_ERROR;
	}

	ngx_module = dyconfig_module->module;
	module = ngx_module->ctx;

	ngx_conf_log_error(NGX_LOG_DEBUG, &cf, 0, 
			"create srv conf module->index:%d.", ngx_module->index);

	original_ctx = (ngx_http_conf_ctx_t *)dyconfig->original_ctx;

	if (module->create_srv_conf) {

		mconf = module->create_srv_conf(&cf);
		if (mconf == NULL) {
			ngx_conf_log_error(NGX_LOG_ERR, &cf, 0, 
					"create srv conf module->index:%d failed.",
					ngx_module->index);
			return NGX_ERROR;
		}

		ctx->srv_conf[ngx_module->ctx_index] = mconf;
	}

	if (module->create_loc_conf) {
		mconf = module->create_loc_conf(&cf);
		if (mconf == NULL) {
			ngx_conf_log_error(NGX_LOG_DEBUG, &cf, 0, 
					"create loc conf module->index:%d failed.", ngx_module->index);
			return NGX_ERROR;
		}


		ctx->loc_conf[ngx_module->ctx_index] = mconf;
	}

	if (module->merge_srv_conf){
		rv = module->merge_srv_conf(&cf, original_ctx->srv_conf[ngx_module->ctx_index],
				ctx->srv_conf[ngx_module->ctx_index]);
		if (rv != NGX_CONF_OK){
			ngx_conf_log_error(NGX_LOG_DEBUG, &cf, 0, 
					"merge srv conf module->index:%d failed.", ngx_module->index);
			return NGX_ERROR;
		}
	}

	if (module->merge_loc_conf){
		rv = module->merge_loc_conf(&cf, original_ctx->loc_conf[ngx_module->ctx_index],
				ctx->loc_conf[ngx_module->ctx_index]);
		if (rv != NGX_CONF_OK){
			ngx_conf_log_error(NGX_LOG_DEBUG, &cf, 0, 
					"merge loc conf module->index:%d failed.", ngx_module->index);
			return NGX_ERROR;
		}
	}

	rc = dyconfig_module->conf_handler(&cf, dyconfig);
	if (rc != NGX_OK){
		return NGX_ERROR;
	}

	return NGX_OK;
}

#if 0
ngx_int_t
ngx_http_dyconfig_init_modules(ngx_http_request_t *r)
{
	ngx_http_conf_ctx_t		*ctx = NULL;
	ngx_http_dyconfig_t		*dyconfig = NULL;

	dyconfig = ngx_http_dyconfig_get_cur(r);
	if (dyconfig == NULL){
		ngx_log_error(NGX_LOG_ERR, r->conneciton->log, 0, 
				"dyconfig cur not set yet error");
		return NGX_ERROR;
	}

	ctx = ngx_palloc(pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, 
				"create srv conf palloc failed.");
        return NGX_ERROR;
    }

	//ctx->main_conf = r->main_conf;	//NOTICE: DO NOT modify main config.

	/* srv_conf */
    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, 
				"create srv conf palloc failed.");
        return NGX_ERROR;
    }

	/* loc_conf */
    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_ERROR;
    }

	dyconfig_module = dyconfig->modules.elts;
    for (m = 0; m < dyconfig->modules.nelts; m++) {

		ngx_module = dyconfig_module[m]->module;
        module = ngx_module->ctx;

		ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, 
				"create srv conf module->index:%d.", ngx_module->index);

        if (module->create_srv_conf) {

            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, 
					"create srv conf module->index:%d failed.",
					ngx_module->index);
                return NGX_ERROR;
            }

            ctx->srv_conf[ngx_module->ctx_index] = mconf;
        }

        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
				ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, 
					"create loc conf module->index:%d failed.", ngx_module->index);
                return NGX_ERROR;
            }

            ctx->loc_conf[ngx_module->ctx_index] = mconf;
        }

		dyconfig_module->conf_handler(r, dyconfig, );


		if (module->merge_srv_conf){
			rc = module->merge_srv_conf(cf, r->srv_conf[module->ctx_index],
					ctx->srv_conf[module->ctx_index]);
			if (rc != NGX_CONF_OK){
				ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, 
					"merge srv conf module->index:%d failed.", ngx_module->index);
				return NGX_ERROR;
			}
		}

		if (module->merge_loc_conf){
			rc = module->merge_loc_conf(cf, r->srv_conf[module->ctx_index],
					ctx->srv_conf[module->ctx_index]);
			if (rc != NGX_CONF_OK){
				ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, 
					"merge loc conf module->index:%d failed.", ngx_module->index);
				return NGX_ERROR;
			}
		}
	}

	dyconfig->ctx = ctx;

	return NGX_OK;
}
#endif

ngx_int_t
ngx_http_conf_dyconfig_set_enable(ngx_conf_t *cf)
{
	ngx_http_dyconfig_loc_conf_t	*dlcf = NULL;

	dlcf = ngx_http_conf_get_module_loc_conf(cf,
					ngx_http_dyconfig_module);

	if (dlcf == NULL){
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "dlcf is null");
		return NGX_ERROR;
	}

	dlcf->enabled = 1;

	return NGX_OK;
}

ngx_int_t
ngx_http_conf_dyconfig_enabled(ngx_conf_t *cf)
{
	ngx_http_dyconfig_loc_conf_t	*dlcf = NULL;

	dlcf = ngx_http_conf_get_module_loc_conf(cf,
					ngx_http_dyconfig_module);

	return (dlcf->enabled == 1);
}

ngx_int_t
ngx_http_dyconfig_enabled(ngx_http_request_t *r)
{
	ngx_http_dyconfig_loc_conf_t	*dlcf = NULL;

	dlcf = ngx_http_get_module_loc_conf(r,
					ngx_http_dyconfig_module);

	return  (dlcf->enabled != NGX_CONF_UNSET);
}

void
ngx_http_dyconfig_need_destroy(ngx_http_dyconfig_t *dyconfig)
{
	dyconfig->times = 0;

	dyconfig->log->action = "dyconfig need destroy";
	ngx_log_error(NGX_LOG_DEBUG, dyconfig->log, 0, "dyconfig need destroy.");

	ngx_queue_remove(&dyconfig->qnode);

	dyconfig->times = 0;
	//TODO:update timer event timeout/random ??
	dyconfig->timeout = dyconfig->timeout / NGX_HTTP_DYCONFIG_DESTROYING_TIMEOUT_BASE_NUM;
	
	if (dyconfig->timeout == 0){
		dyconfig->timeout = 1;
	}

	ngx_add_timer(&dyconfig->timer, dyconfig->timeout);

	ngx_queue_insert_head(&ngx_http_dyconfig.destroying_dyconfigs, &dyconfig->qnode);
}

void
ngx_http_dyconfig_destroy(ngx_http_dyconfig_t *dyconfig)
{
	ngx_event_t					*ev = &dyconfig->timer;
	ngx_http_cleanup_t			*cln = NULL;

	if (dyconfig->destroyed){
		return;
	}

	if (dyconfig->ref > 1 || dyconfig->times){
		dyconfig->ref--;
		dyconfig->log->action = "dyconfig dereference";
		ngx_log_error(NGX_LOG_DEBUG, dyconfig->log, 0, 
				"release dyconfig reference");
		return;
	}

	dyconfig->log->action = "dyconfig destroy";
	ngx_log_error(NGX_LOG_DEBUG, dyconfig->log, 0, "destroy dyconfig(%V)", 
			&dyconfig->name);

	ngx_queue_remove(&dyconfig->qnode);

	if(ev->timer_set){
		ngx_del_timer(ev);
	}

	for(cln = dyconfig->cleanup; cln; cln = cln->next){
		if (cln->handler){
			cln->handler(cln->data);
		}
	}

	ngx_destroy_pool(dyconfig->pool);

	ngx_queue_insert_head(&ngx_http_dyconfig.free_dyconfigs, &dyconfig->qnode);

	dyconfig->destroyed = 1;

	return;
}

static void
ngx_http_dyconfig_timeout_handler(ngx_event_t *ev)
{
	ngx_timer_data_t				*timerdata = NULL;
	ngx_http_dyconfig_t				*dyconfig = NULL;

	timerdata = ev->data;
	dyconfig = timerdata->data;

	dyconfig->log->action = "dyconfig timeout";
	ngx_log_error(NGX_LOG_DEBUG, dyconfig->log, 0, 
		"dyconfig timeout ref:%d, times:%d.", dyconfig->ref, dyconfig->times);

	if (dyconfig->times){

		dyconfig->times = 0;
		//TODO:update timer event timeout/random ??
		if (ev->timer_set){
			ngx_del_timer(ev);
		}
		ngx_add_timer(ev, dyconfig->timeout);
		return;
	}
	
	ngx_http_dyconfig_destroy(dyconfig);

	return;
}

ngx_http_cleanup_t *
ngx_http_dyconfig_cleanup_add(ngx_http_dyconfig_t *dyconfig, size_t size)
{
	ngx_http_cleanup_t		*cln = NULL;

	cln = ngx_palloc(dyconfig->pool, sizeof(ngx_http_cleanup_t));
	if (cln == NULL){
		ngx_log_error(NGX_LOG_DEBUG, dyconfig->log, 0, 
				"http dyconfig add cleanup palloc cln error");
		return NULL;
	}

	if (size){
		cln->data = ngx_palloc(dyconfig->pool, size);
		if (cln->data == NULL){
			ngx_log_error(NGX_LOG_DEBUG, dyconfig->log, 0, 
				"http dyconfig add cleanup palloc data error");
			return NULL;
		}
	}else{
		cln->data = NULL;
	}

	cln->handler = NULL;
	cln->next = dyconfig->cleanup;

	dyconfig->cleanup = cln;

	ngx_log_error(NGX_LOG_DEBUG, dyconfig->log, 0, 
			"http dyconfig add cleanup: %p",cln);

	return cln;
}

static u_char *
ngx_http_dyconfig_log_error(ngx_log_t *log, u_char *buf, size_t	len)
{
    u_char              		*p = NULL;
	ngx_http_dyconfig_t	*dyconfig = log->data;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    p = ngx_snprintf(buf, len, ", dyconfig: %V, ref:%d, times:%d.", 
			&dyconfig->name, dyconfig->ref, dyconfig->times);
    len -= p - buf;

    return p;
}

static void *
ngx_http_dyconfig_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dyconfig_loc_conf_t  *conf = NULL;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dyconfig_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

	conf->enabled = NGX_CONF_UNSET;

    return conf;
}


