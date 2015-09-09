/*
 * =============================================================================
 *
 *       Filename:  ngx_http_connect_pass_module.c
 *    Description:  http connect pass module
 *
 *        Version:  1.0
 *        Created:  2013-10-25 15:05:21
 *       Revision:  none
 *         Author:  mayfengcrazy@163.com, 
 *        Company:  CUN
 *
 * =============================================================================
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define CONNECT_PASS_DEFALUT_CONFIG "/METHOD/CONNECT"

typedef struct {
	ngx_str_t location;

}ngx_http_connect_pass_srv_conf_t;

static ngx_int_t
ngx_http_connect_pass_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_connect_pass_init(ngx_conf_t *cf);
static ngx_int_t
ngx_http_connect_pass_handler(ngx_http_request_t *r);
static void *
ngx_http_connect_pass_create_srv_conf(ngx_conf_t *cf);
static char *
ngx_http_connect_pass_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t  ngx_http_connect_pass_commands[] = {

    { ngx_string("connect_pass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_connect_pass_srv_conf_t, location),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_connect_pass_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_connect_pass_init,   		   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_connect_pass_create_srv_conf, /* create server configuration */
    ngx_http_connect_pass_merge_srv_conf,  /* merge server configuration */

    NULL, 							       /* create location configuration */
    NULL 							       /* merge location configuration */
};


ngx_module_t  ngx_http_connect_pass_module = {
    NGX_MODULE_V1,
    &ngx_http_connect_pass_module_ctx,            /* module context */
    ngx_http_connect_pass_commands,               /* module directives */
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

static ngx_int_t
ngx_http_connect_pass_handler(ngx_http_request_t *r)
{
	ngx_http_connect_pass_srv_conf_t *cpcf = NULL;

	if (!(r->method & (NGX_HTTP_CONNECT))){
    	return NGX_DECLINED;
	}

	if (!(r->connect_start && r->connect_end)){
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_connect_pass_handler param error!");

		//maybe return other value.
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	cpcf = ngx_http_get_module_srv_conf(r, ngx_http_connect_pass_module);

	r->uri = cpcf->location;
	r->internal = 1;

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_connect_pass_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h = NULL;
    ngx_http_core_main_conf_t  *cmcf = NULL;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_connect_pass_handler;

    return NGX_OK;
}

static void *
ngx_http_connect_pass_create_srv_conf(ngx_conf_t *cf)
{
	ngx_http_connect_pass_srv_conf_t *cpcf = NULL;

	cpcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_connect_pass_srv_conf_t));
	if (cpcf == NULL){
		return NULL;
	}

	return cpcf;
}

static char *
ngx_http_connect_pass_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_connect_pass_srv_conf_t *conf = NULL, *prev = NULL;
	
	conf = child;
	prev = parent;

	ngx_conf_merge_str_value(conf->location, prev->location, CONNECT_PASS_DEFALUT_CONFIG);

	return NGX_CONF_OK;
}

