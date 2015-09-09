/*
 * =============================================================================
 *
 *       Filename:  ngx_http_dyconfig_module.h
 *    Description:  dyconfig module
 *
 *        Version:  1.0
 *        Created:  2014-03-24 20:54:42
 *       Revision:  none
 *         Author:  mayfengcrazy@163.com, 
 *        Company:  CUN
 *
 * =============================================================================
 */

typedef struct {
	ngx_str_t					  name;
	ngx_queue_t					  qnode;
	ngx_uint_t					  ref;
	ngx_uint_t					  times;
	ngx_log_t					 *log;
	ngx_pool_t					 *pool;
	ngx_event_t					  timer;
	ngx_msec_t					 timeout;
	void						 **original_ctx;
	void						 **ctx;
	void 						 *data;
	ngx_array_t					 modules;
	ngx_http_cleanup_t			 *cleanup;
	ngx_uint_t					 destroyed;
}ngx_http_dyconfig_t;

typedef ngx_int_t (*ngx_http_dyconfig_conf_handler_pt)(ngx_conf_t *cf, 
		ngx_http_dyconfig_t *dyconfig);

typedef struct {
	ngx_module_t						*module;
	ngx_http_dyconfig_conf_handler_pt	conf_handler;
}ngx_http_dyconfig_module_t;


ngx_int_t
ngx_http_conf_dyconfig_set_enable(ngx_conf_t *cf);
ngx_int_t
ngx_http_dyconfig_enabled(ngx_http_request_t *r);
ngx_int_t
ngx_http_conf_dyconfig_enabled(ngx_conf_t *cf);

ngx_int_t
ngx_http_dyconfig_add_module(ngx_http_request_t *r, 
		ngx_http_dyconfig_t *dyconfig, ngx_http_dyconfig_module_t *dyconfig_module);

ngx_http_cleanup_t *
ngx_http_dyconfig_cleanup_add(ngx_http_dyconfig_t *dyconfig, size_t size);


#define	NGX_HTTP_DYCONFIG_NONE 0x00
#define	NGX_HTTP_DYCONFIG_CURR 0x01
#define	NGX_HTTP_DYCONFIG_FIND 0x02

ngx_http_dyconfig_t *
ngx_http_dyconfig_get(ngx_http_request_t *r, ngx_str_t *name, ngx_uint_t option);
ngx_http_dyconfig_t *
ngx_http_dyconfig_get_cur(ngx_http_request_t *r);
void
ngx_http_dyconfig_destroy(ngx_http_dyconfig_t *dyconfig);
void
ngx_http_dyconfig_need_destroy(ngx_http_dyconfig_t *dyconfig);

#define ngx_http_dyconfig_get_module_main_conf(dyconfig, module)	\
	((ngx_http_conf_ctx_t *)((dyconfig)->ctx))->main_conf[module.ctx_index]

#define ngx_http_dyconfig_get_module_srv_conf(dyconfig, module)	\
	((ngx_http_conf_ctx_t *)((dyconfig)->ctx))->srv_conf[module.ctx_index]

#define ngx_http_dyconfig_get_module_loc_conf(dyconfig, module)	\
	((ngx_http_conf_ctx_t *)((dyconfig)->ctx))->loc_conf[module.ctx_index]

/* Notice: set_ctx address is the same as loc_conf address */
#define ngx_http_dyconfig_set_loc_conf(dyconfig, c, module) \
	((ngx_http_conf_ctx_t *)((dyconfig)->ctx))->loc_conf[module.ctx_index] = c

