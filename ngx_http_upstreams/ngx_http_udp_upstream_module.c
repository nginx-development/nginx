/*
 * =============================================================================
 *
 *       Filename:  ngx_http_udp_upstream_module.c
 *    Description:  http udp upstream module
 *
 *        Version:  1.0
 *        Created:  2013-12-10 19:22:14
 *       Revision:  none
 *         Author:  mayfengcrzay@163.com, 
 *        Company:  CUN
 *
 * =============================================================================
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_upstream_api.c"

static ngx_int_t
ngx_http_udp_upstream_add_upstream_handler(ngx_conf_t *cf);

static void
ngx_http_udp_upstream_process_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
static void
ngx_http_udp_upstream_send_response(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
static void
ngx_http_udp_upstream_send_response_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
static ngx_int_t
ngx_http_udp_upstream_check_connect(ngx_connection_t *c);
#if 0
static void
ngx_http_udp_upstream_init_transfer(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
static ngx_int_t
ngx_http_udp_upstream_non_buffered_filter_init(void *data);
static ngx_int_t
ngx_http_udp_upstream_non_buffered_filter(void *data, ssize_t bytes);
static void
ngx_http_udp_read_handler(ngx_http_request_t *r);
static void
ngx_http_udp_write_handler(ngx_http_request_t *r);
static void
ngx_http_udp_upstream_process_header(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
static void
ngx_http_udp_upstream_write_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
#endif

static void
ngx_http_udp_upstream_dummy_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);


static ngx_http_upstream_instance_t ngx_http_udp_upstream_instance = {
	ngx_string("udp"),
	ngx_http_udp_upstream_process_handler,
};

static ngx_command_t ngx_http_udp_upstream_commands[] = {

	ngx_null_command
};

static ngx_http_module_t ngx_http_udp_upstream_module_ctx = {
	ngx_http_udp_upstream_add_upstream_handler,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

ngx_module_t ngx_http_udp_upstream_module = {
	NGX_MODULE_V1,
	&ngx_http_udp_upstream_module_ctx,
	ngx_http_udp_upstream_commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};


	static ngx_int_t
ngx_http_udp_upstream_add_upstream_handler(ngx_conf_t *cf)
{
	if(ngx_http_upstream_add_upstream_instance(cf, 
				&ngx_http_udp_upstream_instance) != NGX_OK){
		return NGX_ERROR;
	}

	return NGX_OK;
}

	static void
ngx_http_udp_upstream_process_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u)
{
	ngx_int_t          rc = 0;
	ngx_connection_t  *c = NULL;

	rc = ngx_event_connect_udppeer(&u->peer);
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http udp upstream connect: %i", rc);

	if (rc == NGX_ERROR) {
		ngx_http_upstream_finalize_request(r, u,
				NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	u->state->peer = u->peer.name;

	if (rc == NGX_BUSY) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no live upstreams");
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_NOLIVE);
		return;
	}

	if (rc == NGX_DECLINED) {
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
		return;
	}

	/* rc == NGX_OK || rc == NGX_AGAIN */

	c = u->peer.connection;
	c->data = r;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http udp upstream process handler");

	c->read->handler = ngx_http_upstream_handler;
	c->write->handler = ngx_http_upstream_handler;

	u->write_event_handler = ngx_http_udp_upstream_send_response_handler;
	u->read_event_handler = ngx_http_udp_upstream_dummy_handler;

	if (c->pool == NULL) {

		/* we need separate pool here to be able to cache SSL connections */

		c->pool = ngx_create_pool(128, r->connection->log);
		if (c->pool == NULL) {
			ngx_http_upstream_finalize_request(r, u,
					NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}

	c->log = r->connection->log;
	c->pool->log = c->log;
	c->read->log = c->log;
	c->write->log = c->log;

	if (rc == NGX_AGAIN) {
		ngx_add_timer(c->write, u->conf->connect_timeout);
		return;
	}
	/*????
#if (NGX_HTTP_SSL)

	if (u->ssl && c->ssl == NULL) {
		ngx_http_upstream_ssl_init_connection(r, u, c);
		return;
	}

#endif
*/
	ngx_http_udp_upstream_send_response(r, u);
}

	static void
ngx_http_udp_upstream_send_response(ngx_http_request_t *r, 
		ngx_http_upstream_t *u)
{
	ngx_int_t          rc = NGX_OK;
	ngx_connection_t  *c = NULL, *pc = NULL;

	c = r->connection;
	pc = u->peer.connection;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
			"http udp upstream send response");

	if ((ngx_http_upstream_test_connect(pc) != NGX_OK ||
				(rc = ngx_http_udp_upstream_check_connect(pc)) != NGX_OK)) {

		if (rc == NGX_AGAIN){
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
					"http udp upstream send response check eagain.");

			if (!pc->write->timer_set) {
				ngx_add_timer(pc->write, u->conf->connect_timeout);
				return;
			}

			if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
				ngx_log_error(NGX_LOG_ERR, pc->log, 0,
					"http udp upstream handle write event error.");
        		ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        		return;
    		}

			return;
		}

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
				"http udp upstream send response test connect failed.");
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
		return;
	}

	pc->log->action = "sending response to client";

	if (u->create_established_response){

		rc = u->create_established_response(r);
		if (rc != NGX_OK){

			ngx_log_error(NGX_LOG_ERR, pc->log, 0,
					"http udp upstream create established response error.");
			ngx_http_upstream_finalize_request(r, u,
					NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		rc = ngx_http_send_header(r);
		if (rc == NGX_ERROR || rc > NGX_OK ){

				ngx_log_error(NGX_LOG_ERR, pc->log, 0,
					"http udp upstream send header error.");
			ngx_http_upstream_finalize_request(r, u,
					NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

	}

	ngx_upstream_init_transfer(r, u);

	return;
}



	static ngx_int_t
ngx_http_udp_upstream_check_connect(ngx_connection_t *c)
{
	char		buf[1];
	struct sockaddr_in	peeraddr;
	socklen_t	len;
	ngx_int_t	n = 0;
	ngx_err_t	err;
	ngx_int_t	rc = 0;

	n = recv(c->fd, buf, 1, MSG_PEEK);
	err = ngx_socket_errno;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err, 
			"udp upstream check connection recv():%i,fd:%d",
			n, c->fd);

	if(n == 1){

		return NGX_OK;
	}else if(n == -1 && err == NGX_EAGAIN){

		if ((rc = getpeername(c->fd, &peeraddr, &len)) < 0){
			return NGX_ERROR;
		}
		return NGX_OK;
	}else{

		return NGX_ERROR;
	}
}

	static void
ngx_http_udp_upstream_send_response_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u)
{
	ngx_connection_t  *c = NULL;

	c = u->peer.connection;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http upstream send response handler");

	if (c->write->timedout) {
		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
		return;
	}

#if (NGX_HTTP_SSL)

	if (u->ssl && c->ssl == NULL) {
		ngx_http_upstream_ssl_init_connection(r, u, c);
		return;
	}

#endif

	ngx_http_udp_upstream_send_response(r, u);
}


	static void
ngx_http_udp_upstream_dummy_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u)
{
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http udp upstream dummy handler");

}

