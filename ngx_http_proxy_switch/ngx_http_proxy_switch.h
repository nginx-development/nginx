/*
 * =============================================================================
 *
 *       Filename:  ngx_proxy_switch.h
 *    Description:  proxy switch module
 *
 *        Version:  1.0
 *        Created:  2013-12-18 16:36:43
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

typedef ngx_int_t (*ngx_http_proxy_handler_pt)(ngx_http_request_t *r);

typedef struct {
	ngx_str_t		name;
	ngx_http_proxy_handler_pt	handler;
	ngx_http_dyconfig_module_t	*dyconfig_module;
}ngx_http_proxy_instance_t;

typedef struct {
	ngx_str_t					   name;
	ngx_flag_t					   enabled;
	ngx_http_proxy_instance_t	  *proxy;
	ngx_array_t					   proxy_instances;
	ngx_array_t					  *proxy_lengths;
	ngx_array_t					  *proxy_values;
	ngx_int_t					  host_var_index;
	ngx_int_t					  port_var_index;
} ngx_http_proxy_switch_loc_conf_t;

enum{
	PROXY_SWITCH_VAR_UNKNOWN = 0,
	PROXY_SWITCH_VAR_PROTO = 1,
	PROXY_SWITCH_VAR_HOST = 2,
	PROXY_SWITCH_VAR_PORT = 3,
	PROXY_SWITCH_VAR_MAPID = 4
};

ngx_int_t
ngx_http_proxy_switch_set_var(ngx_http_request_t *r, 
		ngx_uint_t var_type, ngx_str_t *value);

ngx_int_t
ngx_http_proxy_switch_set_proxy_instance(ngx_conf_t *cf, 
		ngx_http_proxy_instance_t *instance);

ngx_int_t
ngx_http_proxy_switch_eval(ngx_http_request_t *r, 
		ngx_array_t *proxy_lengths, ngx_array_t *proxy_values);

ngx_int_t
ngx_http_proxy_switch_set_upstream_instance(ngx_conf_t *cf, 
		ngx_http_upstream_conf_t *conf, ngx_str_t *name);

ngx_int_t
ngx_http_proxy_switch_set_upstream_srv_conf(ngx_http_request_t *r, 
		ngx_http_upstream_t *upstream);

ngx_int_t
ngx_http_proxy_dyconfig_enabled(ngx_http_request_t *r);

ngx_int_t
ngx_http_conf_proxy_dyconfig_enabled(ngx_conf_t *cf);

ngx_int_t
ngx_http_proxy_switch_start(ngx_http_request_t *r);

extern ngx_module_t  ngx_http_proxy_switch_module;

