/*
 * =============================================================================
 *
 *       Filename:  ngx_proxy_switch_module.c
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


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_appframe.h>

#include <ngx_http_proxy_switch.h>

typedef struct {
	ngx_str_t					 	proto;
	struct timeval					up_time;
	ngx_http_upstream_srv_conf_t 	*uscf;
	ngx_http_proxy_instance_t	 	*proxy;
}ngx_http_proxy_switch_dyconfig_t;

typedef struct {
    ngx_str_t                      proto;
    ngx_str_t                      host;
    ngx_str_t                      port;
    ngx_str_t                      server;
    ngx_str_t                      mapid;
} ngx_http_proxy_switch_vars_t;

typedef struct {
	ngx_http_proxy_switch_dyconfig_t	*config;
	ngx_http_proxy_switch_vars_t		vars;
}ngx_http_proxy_switch_ctx_t;

static ngx_int_t
ngx_http_proxy_switch_handler(ngx_http_request_t *r);
static char *
ngx_http_proxy_switch(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *
ngx_http_proxy_switch_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_proxy_switch_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

static ngx_int_t
ngx_http_proxy_switch_add_variables(ngx_conf_t *cf);
static ngx_int_t
ngx_http_proxy_switch_proto_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_proxy_switch_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_proxy_switch_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_proxy_switch_server_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_proxy_switch_mapid_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_proxy_switch_set_default_vars(ngx_http_request_t *r);

static ngx_http_proxy_instance_t *
ngx_http_proxy_switch_find_proxy_instance(ngx_http_proxy_switch_loc_conf_t *plcf,
		ngx_str_t *name);

static ngx_http_proxy_switch_dyconfig_t *
ngx_http_proxy_switch_get_config(ngx_http_request_t *r);

static ngx_int_t
ngx_http_proxy_switch_dyconfig_add_server(ngx_http_upstream_create_conf_t *conf, 
		ngx_http_dyconfig_t *dyconfig, ngx_str_t *server, ngx_uint_t port, ngx_uint_t weight);

static ngx_command_t  ngx_http_proxy_switch_commands[] = {
 
    { ngx_string("proxy_switch"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_switch,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_proxy_switch_module_ctx = {
    ngx_http_proxy_switch_add_variables,   /* preconfiguration */
    NULL,								   /* postconfiguration */

    NULL,									/* create main configuration */
	NULL,									/* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxy_switch_create_loc_conf,        /* create location configuration */
    ngx_http_proxy_switch_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_proxy_switch_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_switch_module_ctx,            /* module context */
    ngx_http_proxy_switch_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
	NULL,								   /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_proxy_switch_vars[] = {
	
	{ ngx_string("proxy_switch_proto"), NULL, ngx_http_proxy_switch_proto_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

	{ ngx_string("proxy_switch_server"), NULL, ngx_http_proxy_switch_server_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_switch_host"), NULL, ngx_http_proxy_switch_host_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_switch_port"), NULL, ngx_http_proxy_switch_port_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("proxy_switch_mapid"), NULL, ngx_http_proxy_switch_mapid_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_proxy_switch_handler(ngx_http_request_t *r)
{
	ngx_str_t									proxy_name;
	ngx_http_proxy_instance_t					*proxy = NULL;
	ngx_http_proxy_switch_loc_conf_t			*plcf = NULL;
	ngx_http_proxy_switch_ctx_t					*ctx = NULL;
	ngx_http_proxy_switch_dyconfig_t			*config = NULL;

    ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"proxy switch handler");

	plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_switch_module);

	if (ngx_http_dyconfig_enabled(r)){
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_switch_ctx_t));
		if(ctx == NULL){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"proxy switch handler palloc error");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ngx_http_set_ctx(r, ctx, ngx_http_proxy_switch_module);

		config = ngx_http_proxy_switch_get_config(r);
		if(config == NULL){
        	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"proxy switch get dyconfig error");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		ctx->config = config;

		if (ngx_http_proxy_switch_set_var(r, PROXY_SWITCH_VAR_PROTO, &config->proto) 
				!= NGX_OK){
        	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"proxy switch set var proto error");
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		if (config->uscf->load_balance != 1){
			//set default vars
			if (ngx_http_proxy_switch_set_default_vars(r) != NGX_OK){
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"proxy switch set default vars error");
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
		}

		return config->proxy->handler(r);
	}

	if (ngx_http_script_run(r, &proxy_name, plcf->proxy_lengths->elts, 0,
				plcf->proxy_values->elts) == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"proxy convert script run error");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	proxy = ngx_http_proxy_switch_find_proxy_instance(plcf, &proxy_name);
	if(proxy == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"proxy convert proxy instance not found");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	return proxy->handler(r);
}

static ngx_int_t
ngx_http_proxy_switch_set_default_vars(ngx_http_request_t *r)
{
	ngx_str_t								rvalue = ngx_null_string;
	ngx_http_variable_value_t				*value = NULL;
	ngx_http_proxy_switch_loc_conf_t		*plcf = NULL;

	plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_switch_module);

	if (plcf->host_var_index != NGX_CONF_UNSET){
		value = ngx_http_get_indexed_variable(r, plcf->host_var_index);
		if(value == NULL || value->not_found){
			return NGX_ERROR;
		}
	}

	rvalue.data = value->data;
	rvalue.len = value->len;
	if (ngx_http_proxy_switch_set_var(r, PROXY_SWITCH_VAR_HOST, &rvalue) 
			!= NGX_OK){
		return NGX_ERROR;
	}

	if (plcf->port_var_index != NGX_CONF_UNSET){
		value = ngx_http_get_indexed_variable(r, plcf->port_var_index);
		if(value == NULL || value->not_found){
			return NGX_ERROR;
		}
	}

	if (r->method & NGX_HTTP_CONNECT){

		rvalue.data = r->connect_port_start;
		rvalue.len = r->connect_port_end - r->connect_port_start;
	}else{

		if (plcf->port_var_index != NGX_CONF_UNSET){
			value = ngx_http_get_indexed_variable(r, plcf->port_var_index);
			if(value == NULL || value->not_found){
				return NGX_ERROR;
			}
		}
		rvalue.data = value->data;
		rvalue.len = value->len;
	}

	if (ngx_http_proxy_switch_set_var(r, PROXY_SWITCH_VAR_PORT, &rvalue)
			!= NGX_OK){
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_proxy_switch_set_record(ngx_http_proxy_switch_dyconfig_t *config, 
		ngx_access_t *access)
{
	ngx_resource_group_t		*group = NULL;
	ngx_resource_t				*rsc = NULL;

	if (ngx_access_is_group(access)){
		group = (ngx_resource_group_t *)access->data;
		if (group == NULL){
			return NGX_ERROR;
		}

		config->up_time = group->up_time;

	}else{
		rsc = (ngx_resource_t *)access->data;
		if (rsc == NULL){
			return NGX_ERROR;
		}

		config->up_time = rsc->up_time;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_timeval_compare(struct timeval *t1, struct timeval *t2)
{
	return (t1->tv_sec != t2->tv_sec) || (t1->tv_usec != t2->tv_usec);
}

static ngx_int_t
ngx_http_proxy_switch_check_resource_update(ngx_http_proxy_switch_dyconfig_t *config, 
		ngx_access_t *access)
{
	ngx_resource_group_t 		*group = NULL;
	ngx_resource_t				*rsc = NULL;
	struct timeval				up_time;

	if (ngx_access_is_group(access)){
		group = (ngx_resource_group_t *)access->data;
		if (group == NULL){
			//must some problem with appcache, so do not update dyconfig.
			return 0;
		}

		up_time = group->up_time;

	}else{

		rsc = (ngx_resource_t *)access->data;
		if (rsc == NULL){
			//must some problem with appcache, so do not update dyconfig.
			return 0;
		}

		up_time = rsc->up_time;
	}

	if (ngx_timeval_compare(&config->up_time, &up_time)){
		return 1;
	}

	return 0;
}

static ngx_http_proxy_switch_dyconfig_t *
ngx_http_proxy_switch_get_config(ngx_http_request_t *r)
{
	ngx_conf_t								cf;
	ngx_int_t								rc = 0;
	ngx_str_t								*proxy_name = NULL, proto = ngx_null_string;
	ngx_str_t								mapid = ngx_null_string;
	ngx_url_t								url;
	ngx_resource_t							*rsc = NULL;
	ngx_http_conf_ctx_t						*ctx = NULL;
	ngx_http_proxy_instance_t				*proxy = NULL;
	ngx_http_proxy_switch_loc_conf_t		*plcf = NULL;
	ngx_http_upstream_srv_conf_t			*uscf = NULL;
	ngx_http_dyconfig_t						*dyconfig = NULL;
	ngx_http_proxy_switch_dyconfig_t		*config = NULL;
	ngx_http_upstream_create_conf_t	 		 conf;

	ngx_access_t							*access = NULL;
	ngx_resource_group_t 					*group = NULL;
	ngx_resource_member_t 					*member = NULL;
	ngx_queue_t 							*q = NULL;
	ngx_queue_t 							*tq = NULL;
	ngx_port_range_t						*elts = NULL;

	access = ngx_http_request_access_curr(r);

	if (NULL == access) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"request access curr error.");
		return NULL;
	}

	switch(access->type){
		case NGX_RESOURCE_TYPE_GROUP:
			group = ngx_http_request_group_curr(r);
			if (group == NULL){
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"user match get resource group error.");
				return NULL;
			}

			mapid = group->mapid;
			
			if (ngx_queue_empty(&group->member_queue)){
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"user match get resource group member is empty.");
				return NULL;
			}

			q = ngx_queue_head(&group->member_queue);
			member = ngx_queue_data(q, ngx_resource_member_t, group_member_qnode);

			rsc = member->rsc;
			if (rsc == NULL){
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"user match get resource error.");
				return NULL;
			}
			
			break;
		default:
			rsc = ngx_http_request_resource_curr(r);
			if (rsc == NULL){
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"user match get resource error.");
				return NULL;
			}

			mapid = rsc->mapid;
			break;
	}

	if(ngx_http_proxy_switch_set_var(r, PROXY_SWITCH_VAR_MAPID, &mapid) 
			!= NGX_OK){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"proxy switch set var mapid error.");
		return NULL;
	}

	dyconfig = ngx_http_dyconfig_get(r, &mapid, 
			NGX_HTTP_DYCONFIG_FIND | NGX_HTTP_DYCONFIG_CURR);
	if (dyconfig == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"get dyconfig error.");
		return NULL;
	}

	config = ngx_http_dyconfig_get_module_loc_conf(dyconfig, ngx_http_proxy_switch_module);
	if (config != NULL){
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
				"get dyconfig have config.");

		if (ngx_http_proxy_switch_check_resource_update(config, access) != 0){
			ngx_http_dyconfig_need_destroy(dyconfig);

			dyconfig = ngx_http_dyconfig_get(r, &mapid, NGX_HTTP_DYCONFIG_NONE);
			if (dyconfig == NULL){
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
					"get dyconfig update failed.");
				return NULL;
			}
		}else{

			return config;
		}
	}

	ngx_memzero(&conf, sizeof(conf));
	conf.name = mapid;

	if (ngx_array_init(&conf.servers, 
				r->pool, 4, sizeof(ngx_http_upstream_server_conf_t *)) != NGX_OK){

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"proxy switch get config instance: array init error");
		ngx_http_dyconfig_destroy(dyconfig);
		return NULL;
	}

	switch (rsc->type){
		case NGX_RESOURCE_TYPE_WEB:
			switch (rsc->proto){
				case NGX_RESOURCE_PROTO_HTTP:
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
						"web resource http");

					ngx_str_set(&proto, "http");
					break;
				case NGX_RESOURCE_PROTO_HTTPS:
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
						"web resource https");

					ngx_str_set(&proto, "https");
					break;
				default :
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
						"proxy switch unknown web proto type");
					ngx_http_dyconfig_destroy(dyconfig);
					return NULL;
			}

			ngx_str_set(&conf.proxy_name, "http_proxy");
			conf.balance_name.len = 0;

			if (access->type == NGX_RESOURCE_TYPE_GROUP){

				ngx_str_set(&conf.balance_name, "session_sticky");

				for (q = ngx_queue_head(&group->member_queue), tq = ngx_queue_next(q);
						q != ngx_queue_sentinel(&group->member_queue);
						q = tq, tq = ngx_queue_next(q)) {
					member = ngx_queue_data(q, ngx_resource_member_t, group_member_qnode);
					rsc = member->rsc;

					if (rsc == NULL){
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
								"proxy switch bs group add server resource is null");
						ngx_http_dyconfig_destroy(dyconfig);
						return NULL;
					}
					
					ngx_memzero(&url, sizeof(ngx_url_t));
					url.url.len = rsc->web_addr.len;
					url.url.data = rsc->web_addr.data;
					url.default_port = 80;
					url.uri_part = 1;
					url.no_resolve = 1;

					if (ngx_parse_url(r->pool, &url) != NGX_OK) {
						if (url.err) {
							ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
									"%s in dyconfig upstream \"%V\"", url.err, &url.url);
						}

						ngx_http_dyconfig_destroy(dyconfig);
						return NULL;
					}

					if (ngx_inet_addr(url.host.data, url.host.len) == INADDR_NONE){
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
							"proxy switch bs group add server: DO NOT SUPPORT DOMAIN CONFIG.");
						ngx_http_dyconfig_destroy(dyconfig);
						return NULL;
					}

					if (ngx_http_proxy_switch_dyconfig_add_server(&conf, dyconfig, 
								&rsc->web_addr, rsc->web_port, member->weight) != NGX_OK) {
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
								"proxy switch bs group add server error");
						ngx_http_dyconfig_destroy(dyconfig);
						return NULL;
					}
				}

			}else{

				ngx_memzero(&url, sizeof(ngx_url_t));
				url.url.len = rsc->web_addr.len;
				url.url.data = rsc->web_addr.data;
				url.default_port = 80;
				url.uri_part = 1;
				url.no_resolve = 1;

				if (ngx_parse_url(r->pool, &url) != NGX_OK) {
					if (url.err) {
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
								"%s in dyconfig upstream \"%V\"", url.err, &url.url);
					}

					ngx_http_dyconfig_destroy(dyconfig);
					return NULL;
				}

				if (ngx_inet_addr(url.host.data, url.host.len) == INADDR_NONE){
					conf.domain = 1;
					break;
				}

				if (ngx_http_proxy_switch_dyconfig_add_server(&conf, dyconfig, 
							&rsc->web_addr, rsc->web_port, 0) != NGX_OK){
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
							"proxy switch bs add server error");
					ngx_http_dyconfig_destroy(dyconfig);
					return NULL;
				}

			}
			break;
		case NGX_RESOURCE_TYPE_TCPUDP:
			switch (rsc->proto){
				case NGX_RESOURCE_PROTO_TCP:
				case NGX_RESOURCE_PROTO_HTTP:
				case NGX_RESOURCE_PROTO_HTTPS:
				case NGX_RESOURCE_PROTO_TELNET:
				case NGX_RESOURCE_PROTO_IMAP:
				case NGX_RESOURCE_PROTO_LDAP:
				case NGX_RESOURCE_PROTO_MYSQL:
				case NGX_RESOURCE_PROTO_ORACLE:
				case NGX_RESOURCE_PROTO_POP3:
				case NGX_RESOURCE_PROTO_SMB:
				case NGX_RESOURCE_PROTO_SMTP:
				case NGX_RESOURCE_PROTO_SQLSERVER:
					ngx_str_set(&conf.proxy_name, "tcp_proxy");

					ngx_str_set(&proto, "tcp");
					break;
				case NGX_RESOURCE_PROTO_UDP:
				case NGX_RESOURCE_PROTO_TFTP:
				case NGX_RESOURCE_PROTO_DNS:
					ngx_str_set(&conf.proxy_name, "udp_proxy");

					ngx_str_set(&proto, "udp");
					break;
				case NGX_RESOURCE_PROTO_FTP:
					ngx_str_set(&conf.proxy_name, "ftp_proxy");

					ngx_str_set(&proto, "ftp");
					break;
				default:
					ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
							"proxy proto not support error.");
					ngx_http_dyconfig_destroy(dyconfig);
					return NULL;
			}

			if (access->type == NGX_RESOURCE_TYPE_GROUP){

				ngx_str_set(&conf.balance_name, "session_sticky");

				for (q = ngx_queue_head(&group->member_queue), tq = ngx_queue_next(q);
						q != ngx_queue_sentinel(&group->member_queue);
						q = tq, tq = ngx_queue_next(q)) {
					member = ngx_queue_data(q, ngx_resource_member_t, group_member_qnode);
					rsc = member->rsc;

					if (rsc == NULL){
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
								"proxy switch cs group add server resource is null");
						ngx_http_dyconfig_destroy(dyconfig);
						return NULL;
					}

					ngx_memzero(&url, sizeof(ngx_url_t));
					url.url.len = rsc->tcpudp_addr.len;
					url.url.data = rsc->tcpudp_addr.data;
					url.default_port = 80;
					url.uri_part = 1;
					url.no_resolve = 1;

					if (ngx_parse_url(r->pool, &url) != NGX_OK) {
						if (url.err) {
							ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
									"%s in dyconfig upstream \"%V\"", url.err, &url.url);
						}

						ngx_http_dyconfig_destroy(dyconfig);
						return NULL;
					}

					if (ngx_inet_addr(url.host.data, url.host.len) == INADDR_NONE){
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
							"proxy switch cs group add server: DO NOT SUPPORT DOMAIN CONFIG.");
						ngx_http_dyconfig_destroy(dyconfig);
						return NULL;
					}

					//tcpudp load balance port is single.
					elts = NGX_SETOF_ELTS(rsc->tcpudp_ports);

					if (ngx_http_proxy_switch_dyconfig_add_server(&conf, dyconfig, 
								&rsc->tcpudp_addr, elts[0].start, member->weight) 
								!= NGX_OK){
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
								"proxy switch cs group add server error");
						ngx_http_dyconfig_destroy(dyconfig);
						return NULL;
					}

				}

			}else{

				ngx_memzero(&url, sizeof(ngx_url_t));
				url.url.len = rsc->tcpudp_addr.len;
				url.url.data = rsc->tcpudp_addr.data;
				url.default_port = 80;
				url.uri_part = 1;
				url.no_resolve = 1;

				if (ngx_parse_url(r->pool, &url) != NGX_OK) {
					if (url.err) {
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
								"%s in dyconfig upstream \"%V\"", url.err, &url.url);
					}

					ngx_http_dyconfig_destroy(dyconfig);
					return NULL;
				}

				if (ngx_inet_addr(url.host.data, url.host.len) == INADDR_NONE){
					conf.domain = 1;
					break;
				}

				if (ngx_http_proxy_switch_dyconfig_add_server(&conf, dyconfig, 
							&rsc->tcpudp_addr, 0, 0) != NGX_OK){
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
							"proxy switch cs add server error");
					ngx_http_dyconfig_destroy(dyconfig);
					return NULL;
				}

			}

			break;
		case NGX_RESOURCE_TYPE_REMOTE:
			ngx_str_set(&conf.proxy_name, "tcp_proxy");

			ngx_str_set(&proto, "tcp");

			if (access->type == NGX_RESOURCE_TYPE_GROUP){
				
				ngx_str_set(&conf.balance_name, "session_sticky");

				for (q = ngx_queue_head(&group->member_queue), tq = ngx_queue_next(q);
						q != ngx_queue_sentinel(&group->member_queue);
						q = tq, tq = ngx_queue_next(q)) {
					member = ngx_queue_data(q, ngx_resource_member_t, group_member_qnode);
					rsc = member->rsc;

					if (rsc == NULL){
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
								"proxy switch remote group add server resource is null");
						ngx_http_dyconfig_destroy(dyconfig);
						return NULL;
					}
					
					//remote load balance port is single.
					elts = NGX_SETOF_ELTS(rsc->remote_ports);

					if (ngx_http_proxy_switch_dyconfig_add_server(&conf, dyconfig, 
								&rsc->remote_addr, elts[0].start, member->weight) != NGX_OK){
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
								"proxy switch remote group add server error");
						ngx_http_dyconfig_destroy(dyconfig);
						return NULL;
					}

				}

			}else{

				if (ngx_http_proxy_switch_dyconfig_add_server(&conf, dyconfig, 
							&rsc->remote_addr, 0, 0) != NGX_OK){
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
							"proxy switch remote add server error");
					ngx_http_dyconfig_destroy(dyconfig);
					return NULL;
				}

			}

			break;
		default:
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
					"proxy type not support error.");
			ngx_http_dyconfig_destroy(dyconfig);
			return NULL;
	}

	//NOTICE: pool
	config = ngx_pcalloc(dyconfig->pool, sizeof(ngx_http_proxy_switch_dyconfig_t));
	if(config == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"upstream create srv conf alloc config failed");
		ngx_http_dyconfig_destroy(dyconfig);
		return NULL;
	}

	config->proto = proto;
	if (ngx_http_proxy_switch_set_record(config, access) != NGX_OK){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"proxy switch set record failed");
		ngx_http_dyconfig_destroy(dyconfig);
		return NULL;
	}

	ngx_memzero(&cf, sizeof(ngx_conf_t));
	cf.log = dyconfig->log;
	cf.pool = dyconfig->pool;

	ctx = ngx_palloc(r->pool, sizeof(ngx_http_conf_ctx_t));
	if(ctx == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"upstream create srv conf alloc ctx failed");
		ngx_http_dyconfig_destroy(dyconfig);
		return NULL;
	}

	cf.ctx = ctx;
	ctx->main_conf = r->main_conf;

	uscf = ngx_http_upstream_create_srv_conf(&cf, &conf);
	if(uscf == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"upstream create srv conf failed");
		ngx_http_dyconfig_destroy(dyconfig);
		return NULL;
	}
	config->uscf = uscf;

	if (access->type == NGX_RESOURCE_TYPE_GROUP){
		uscf->load_balance = 1;
	}else{
		uscf->load_balance = 0;
	}

	proxy_name = &conf.proxy_name;
	plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_switch_module);
	proxy = ngx_http_proxy_switch_find_proxy_instance(plcf, proxy_name);
	if(proxy == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"get proxy instance(%V) failed", proxy_name);
		ngx_http_dyconfig_destroy(dyconfig);
		return NULL;
	}
	
	//add dyconfig module
	if (proxy->dyconfig_module){
		rc = ngx_http_dyconfig_add_module(r, dyconfig, proxy->dyconfig_module);
		if (rc != NGX_OK){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
					"dyconfig add module failed");
			ngx_http_dyconfig_destroy(dyconfig);
			return NULL;
		}
	}

	config->proxy = proxy;

	ngx_http_dyconfig_set_loc_conf(dyconfig, config, ngx_http_proxy_switch_module);

	return config;
}

static ngx_int_t
ngx_http_proxy_switch_dyconfig_add_server(ngx_http_upstream_create_conf_t *conf, 
		ngx_http_dyconfig_t *dyconfig, ngx_str_t *server, ngx_uint_t port, ngx_uint_t weight)
{
	u_char									*buf = NULL;
	ngx_uint_t								len = 0;
	ngx_http_upstream_server_conf_t		    **serverp = NULL, *s = NULL;

	serverp = ngx_array_push(&conf->servers);
	if (serverp == NULL){
		ngx_log_error(NGX_LOG_ERR, dyconfig->log, 0, 
				"proxy switch dyconfig add server push error");
		return NGX_ERROR;
	}

	s = ngx_pcalloc(dyconfig->pool, sizeof(*s));
	if (s == NULL){
		ngx_log_error(NGX_LOG_ERR, dyconfig->log, 0, 
				"proxy switch dyconfig add server mem full");
		return NGX_ERROR;
	}

	len = server->len + 1;
	buf = ngx_pcalloc(dyconfig->pool, len);
	if (buf == NULL){
		ngx_log_error(NGX_LOG_ERR, dyconfig->log, 0, 
				"proxy switch dyconfig add server mem full.");
		return NGX_ERROR;
	}

	ngx_cpystrn(buf, server->data, len);

	s->url.data = buf;
	s->url.len = ngx_strlen(buf);
	if (port != 0){
		s->port = port;
	}
	s->weight = (weight == 0 ? 1 : weight);
	*serverp = s;

	ngx_log_error(NGX_LOG_DEBUG, dyconfig->log, 0, 
		"proxy switch dyconfig add server:(%V:%d) weight:%d.",
		&s->url, s->port, s->weight);

	return NGX_OK;
}

static char *
ngx_http_proxy_switch(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_uint_t                  		n = 0;
	ngx_int_t							rc = 0;
    ngx_str_t                  			*value = NULL, *proxy_name = NULL;
	ngx_str_t							var_name = ngx_null_string;
    ngx_http_core_loc_conf_t   			*clcf = NULL;
    ngx_http_script_compile_t   		sc;
    ngx_http_proxy_switch_loc_conf_t 	*plcf = conf;

	if (plcf->enabled == 1){
		return "is duplicate";
	}

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	
	clcf->handler = ngx_http_proxy_switch_handler;
	plcf->enabled = 1;

    value = cf->args->elts;
	proxy_name = &value[1];

    n = ngx_http_script_variables_count(proxy_name);

    if (n) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = proxy_name;
        sc.lengths = &plcf->proxy_lengths;
        sc.values = &plcf->proxy_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

	if (ngx_strncmp(value[1].data, "dyconfig", 8) == 0){
		rc = ngx_http_conf_dyconfig_set_enable(cf);
		if (rc != NGX_OK){
			return "dyconfig set enable failed";
		}

		ngx_str_set(&var_name, "resource_addr");
		plcf->host_var_index = ngx_http_get_variable_index(cf, &var_name);
		if(plcf->host_var_index == NGX_ERROR){
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, 
					"proxy switch var(%V) not found", 
					&var_name);
			return NGX_CONF_ERROR;
		}

		ngx_str_set(&var_name, "resource_port");
		plcf->port_var_index = ngx_http_get_variable_index(cf, &var_name);
		if(plcf->port_var_index == NGX_ERROR){
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, 
					"proxy switch var(%V) not found", 
					&var_name);
			return NGX_CONF_ERROR;
		}

        return NGX_CONF_OK;
	}


	plcf->name = *proxy_name;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_proxy_switch_proto_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_switch_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.proto.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.proto.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_proxy_switch_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_switch_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.host.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.host.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_switch_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_switch_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.port.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.port.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_proxy_switch_server_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_switch_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.server.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.server.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_proxy_switch_mapid_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_switch_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.mapid.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.mapid.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_switch_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_proxy_switch_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static void *
ngx_http_proxy_switch_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_switch_loc_conf_t  *conf = NULL;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_switch_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->proxy_instances, cf->pool, 4,
                       sizeof(ngx_http_proxy_instance_t *)) != NGX_OK)
    {
        return NULL;
    }

	conf->enabled = NGX_CONF_UNSET;
	conf->proxy = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *
ngx_http_proxy_switch_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf)
{
	ngx_http_core_loc_conf_t   			*clcf = NULL;
	ngx_http_proxy_switch_loc_conf_t	*plcf = conf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	if (plcf->enabled == 1){

		if ((plcf->proxy_lengths == NULL) 
				&& (!ngx_http_conf_dyconfig_enabled(cf))){

			ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "proxy switch:%V", 
					&plcf->name);

			plcf->proxy = ngx_http_proxy_switch_find_proxy_instance(plcf,
					&plcf->name);

			if(plcf->proxy == NULL){
				return "proxy convert Unknown proxy instance";
			}

			if (plcf->proxy->handler == NULL){
				return "proxy instance handler empty";
			}

			clcf->handler = plcf->proxy->handler;
		}else{

			ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "proxy switch handler");

			clcf->handler = ngx_http_proxy_switch_handler;
		}
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_proxy_switch_add_proxy_instance(ngx_http_proxy_switch_loc_conf_t *plcf, 
	ngx_http_proxy_instance_t *instance)
{
	ngx_http_proxy_instance_t	**instancep = NULL;

	if (ngx_http_proxy_switch_find_proxy_instance(plcf, &instance->name) 
			!= NULL){
		return NGX_ERROR;
	}

	instancep = ngx_array_push(&plcf->proxy_instances);
    if (instancep == NULL) {
        return NGX_ERROR;
    }

	*instancep = instance;
	return NGX_OK;
}

static ngx_http_proxy_instance_t *
ngx_http_proxy_switch_find_proxy_instance(ngx_http_proxy_switch_loc_conf_t *plcf,
		ngx_str_t *name)
{
	ngx_uint_t	 				i = 0;
	ngx_http_proxy_instance_t	**instancep = NULL;

	instancep = plcf->proxy_instances.elts;
	for ( i = 0; i < plcf->proxy_instances.nelts; i++){

		if (instancep[i]->name.len == name->len
				&& ngx_strncasecmp(instancep[i]->name.data, 
					name->data, name->len) == 0)
		{
			return instancep[i];
		}
	}

	return NULL;
}

ngx_int_t
ngx_http_proxy_switch_set_proxy_instance(ngx_conf_t *cf, 
		ngx_http_proxy_instance_t *instance)
{
    ngx_http_core_loc_conf_t  			*clcf = NULL;
	ngx_http_proxy_switch_loc_conf_t	*plcf = NULL;

	if (instance == NULL 
			|| instance->name.len == 0
			|| instance->handler == NULL){

		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, 
				"add proxy instance input param wrong");
		return NGX_ERROR;
	}

   	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	plcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_switch_module);

	if (plcf->enabled == 1 ){

		ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "proxy switch enabled");

		if(ngx_http_proxy_switch_add_proxy_instance(plcf, instance) != NGX_OK){
		
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, 
					"add proxy instance(%V) failed", &instance->name);
			return NGX_ERROR;
		}

		return NGX_OK;
	}

   	clcf->handler = instance->handler;

	return NGX_OK;
}

ngx_int_t
ngx_http_proxy_switch_set_upstream_instance(ngx_conf_t *cf, 
		ngx_http_upstream_conf_t *conf, ngx_str_t *name)
{
	ngx_http_upstream_instance_t	*instance = NULL;

	instance = ngx_http_upstream_find_upstream_instance(cf, name);
	if(instance == NULL){

		return NGX_ERROR;
	}

	conf->upstream_instance = instance;

	return NGX_OK;
}

ngx_int_t
ngx_http_proxy_switch_set_upstream_srv_conf(ngx_http_request_t *r, 
		ngx_http_upstream_t *upstream)
{
	ngx_http_proxy_switch_ctx_t			*ctx = NULL;
	ngx_http_proxy_switch_dyconfig_t  	*config = NULL;

	ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);

	if (ctx == NULL){

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "input param wrong");
		return NGX_ERROR;
	}

	config = ctx->config;
	if (config == NULL || config->uscf == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "config uscf is null");
		return NGX_ERROR;
	}

	upstream->uscf = config->uscf;

	return NGX_OK;
}

ngx_int_t
ngx_http_proxy_switch_eval(ngx_http_request_t *r, 
		ngx_array_t *proxy_lengths, ngx_array_t *proxy_values)
{
	u_short				  		port = 80;
    ngx_str_t             		proxy = ngx_null_string;
    ngx_str_t             		proto = ngx_null_string;
	ngx_url_t			  		url;
    ngx_http_upstream_t  		*u = NULL;
	
    u = r->upstream;

    if (ngx_http_script_run(r, &proxy, proxy_lengths->elts, 0,
                            proxy_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

	proto.data = proxy.data;
	proxy.data = ngx_strstrn(proxy.data, "://", 2);
	if (proxy.data == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
       			"proxy var format wrong.");
		return NGX_ERROR;
	}
	proto.len = proxy.data - proto.data;
	proxy.data += 3;
	proxy.len = proto.data + proxy.len - proxy.data;

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url = proxy;
    url.default_port = port;
	url.uri_part = 1;
    url.no_resolve = 1;

    if (ngx_parse_url(r->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
		return NGX_ERROR;
	}

	if (url.addrs && url.addrs[0].sockaddr){
		u->resolved->sockaddr = url.addrs[0].sockaddr;
		u->resolved->socklen = url.addrs[0].socklen;
		u->resolved->naddrs = 1;
		u->resolved->host = url.addrs[0].name;

	}else{
		u->resolved->host = url.host;
		u->resolved->port = (in_port_t) (url.no_port ? port : url.port);
		u->resolved->no_port = url.no_port;
	}
    return NGX_OK;
}

ngx_int_t
ngx_http_proxy_switch_set_var(ngx_http_request_t *r, 
		ngx_uint_t var_type, ngx_str_t *value)
{
	ngx_int_t							len = 0;
	ngx_http_proxy_switch_ctx_t			*ctx = NULL;

	ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_switch_module);
	if (ctx == NULL || value == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"proxy switch set var %s", 
				ctx == NULL ? "ctx is null" : "input value wrong");
		return NGX_ERROR;
	}

	switch (var_type){
		case PROXY_SWITCH_VAR_PROTO:
			ctx->vars.proto = *value;
			break;
		case PROXY_SWITCH_VAR_HOST:
			ctx->vars.host = *value;
			ctx->vars.server = *value;
			break;
		case PROXY_SWITCH_VAR_PORT:
			ctx->vars.port = *value;
			if ((value->len != 0) 
					&& (((ngx_strncmp(ctx->vars.proto.data, "https", 5) == 0) 
							&& (ngx_strncmp(value->data, "443", 3) != 0))
						|| ((ngx_strncmp(ctx->vars.proto.data, "http", 4) == 0)
							&& (ngx_strncmp(ctx->vars.proto.data, "https", 5) != 0)
							&& (ngx_strncmp(value->data, "80", 2) != 0)))){

				len = ctx->vars.host.len + value->len;
				ctx->vars.server.data = ngx_pcalloc(r->pool, len + 2);
				if (ctx->vars.server.data == NULL){
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
							"proxy switch set var pcalloc error");
					return NGX_ERROR;
				}

				ngx_snprintf(ctx->vars.server.data, len + 2 ,"%s:%s", 
						ctx->vars.host.data, ctx->vars.port.data);
				ctx->vars.server.len  = len + 1;

			}
			break;
		case PROXY_SWITCH_VAR_MAPID:
			ctx->vars.mapid = *value;
			break;
		default :
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"proxy switch set var unknown var type");
			return NGX_ERROR;
	}

	return NGX_OK;
}

ngx_int_t
ngx_http_proxy_switch_start(ngx_http_request_t *r)
{
	//NOTICE: same function as ready_client_body
	r->main->count++;
	ngx_http_upstream_init(r);

	return NGX_DONE;
}

