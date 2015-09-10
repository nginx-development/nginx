/*
 * =============================================================================
 *
 *       Filename:  ngx_http_tcp_upstream_module.c
 *    Description:  http tcp upstream module
 *
 *        Version:  1.0
 *        Created:  2013-12-10 19:22:14
 *       Revision:  none
 *         Author:  mayfengcrazy@163.com, 
 *        Company:  CUN
 *
 * =============================================================================
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_upstream_api.c"

static ngx_int_t
ngx_http_tcp_upstream_add_upstream_handler(ngx_conf_t *cf);

static void
ngx_http_tcp_upstream_process_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
static void
ngx_http_tcp_upstream_send_response(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
static void
ngx_http_tcp_upstream_send_response_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
#if 0
static void
ngx_http_tcp_upstream_handler(ngx_event_t *ev);
static void
ngx_http_tcp_proxy_handler(ngx_event_t *ev);
#endif
static void
ngx_http_tcp_upstream_dummy_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
static ngx_int_t
ngx_http_tcp_upstream_check_connect(ngx_connection_t *c);


static ngx_http_upstream_instance_t ngx_http_tcp_upstream_instance = {
	ngx_string("tcp"),
	ngx_http_tcp_upstream_process_handler,
};

static ngx_command_t ngx_http_tcp_upstream_commands[] = {

	ngx_null_command
};

static ngx_http_module_t ngx_http_tcp_upstream_module_ctx = {
	ngx_http_tcp_upstream_add_upstream_handler,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

ngx_module_t ngx_http_tcp_upstream_module = {
	NGX_MODULE_V1,
	&ngx_http_tcp_upstream_module_ctx,
	ngx_http_tcp_upstream_commands,
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
ngx_http_tcp_upstream_add_upstream_handler(ngx_conf_t *cf)
{

	if (ngx_http_upstream_add_upstream_instance(cf, 
				&ngx_http_tcp_upstream_instance) != NGX_OK){
		return NGX_ERROR;
	}

	return NGX_OK;
}

static void
ngx_http_tcp_upstream_process_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc = 0;
    ngx_connection_t  *c = NULL;

    rc = ngx_event_connect_peer(&u->peer);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http tcp upstream connect: %i", rc);

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
                   "http tcp upstream process handler");

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

	r->write_event_handler = ngx_http_request_empty_handler;

    c->write->handler = ngx_http_upstream_handler;
    c->read->handler = ngx_http_upstream_handler;

    u->write_event_handler = ngx_http_tcp_upstream_send_response_handler;
    u->read_event_handler = ngx_http_tcp_upstream_dummy_handler;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }
/*
#if (NGX_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        ngx_http_upstream_ssl_initpc->readonnection(r, u, c);
        return;
    }

#endif
*/
    ngx_http_tcp_upstream_send_response(r, u);
}

static void
ngx_http_tcp_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc = NGX_OK;
    ngx_connection_t  *c = NULL, *pc = NULL;

	c = r->connection;
    pc = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "http tcp upstream send response");

    if ((ngx_http_upstream_test_connect(pc) != NGX_OK ||
				(rc = ngx_http_tcp_upstream_check_connect(pc)) != NGX_OK)) {

		if (rc == NGX_AGAIN){
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
					"http tcp upstream send response check eagain.");

			if (!pc->write->timer_set) {
				ngx_add_timer(pc->write, u->conf->connect_timeout);
				return;
			}

			if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
				ngx_log_debug0(NGX_LOG_ERR, pc->log, 0,
					"http tcp upstream handle write event error.");
        		ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        		return;
    		}

			return;
		}

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "http tcp upstream send response test connect failed.");
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    pc->log->action = "sending response to client";

	if (u->create_established_response && u->response_sent != 1){

		rc = u->create_established_response(r);
		if (rc != NGX_OK){

			ngx_log_error(NGX_LOG_ERR, pc->log, 0,
					"http tcp upstream create established response error.");
        	ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
		
		rc = ngx_http_send_header(r);
		if (rc == NGX_ERROR || rc > NGX_OK ){

			ngx_log_error(NGX_LOG_ERR, pc->log, 0,
					"http tcp upstream send header error.");
			ngx_http_upstream_finalize_request(r, u,
					NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
		
		u->response_sent = 1;
	}

	ngx_upstream_init_transfer(r, u);

	return;
}

static ngx_int_t
ngx_http_tcp_upstream_check_connect(ngx_connection_t *c)
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
			"tcp upstream check connection recv():%i,fd:%d",
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
ngx_http_tcp_upstream_send_response_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
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

    ngx_http_tcp_upstream_send_response(r, u);
}

#if 0
static void
ngx_http_tcp_upstream_handler(ngx_event_t *ev)
{
    ngx_connection_t     *c = NULL;
    ngx_http_request_t   *r = NULL;
    ngx_http_upstream_t  *u = NULL;

    c = ev->data;
    r = c->data;

    u = r->upstream;
    c = r->connection;

    if (ev->write) {
    	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http tcp upstream write event handler");
        u->write_event_handler(r, u);

    } else {
    	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http tcp upstream read event handler");
        u->read_event_handler(r, u);
    }
}

static void
ngx_http_tcp_proxy_handler(ngx_event_t *ev) 
{
    char                     *action = NULL, *recv_action = NULL, *send_action = NULL;
    off_t                    *read_bytes = NULL, *write_bytes = NULL;
    size_t                    size = 0;
    ssize_t                   n = 0;
    ngx_buf_t                *b = NULL;
    ngx_err_t                 err;
    ngx_uint_t                do_write, first_read;
    ngx_connection_t         *c = NULL, *src = NULL, *dst = NULL;
    ngx_http_request_t       *r = NULL;
	ngx_http_upstream_t		 *u = NULL;

    c = ev->data;
    r = c->data;
	u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http tcp upstream handler");

    if (ev->timedout) {

        c->log->action = "http tcp upstream proxying";

        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "tcp proxy timed out");
        c->timedout = 1;

		ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    read_bytes = NULL;
    write_bytes = NULL;

    if (c == r->connection) {
        if (ev->write) {
            recv_action = "client write: proxying and reading from upstream";
            send_action = "client write: proxying and sending to client";
            src = r->upstream->peer.connection;
            dst = c;
            b = &r->upstream->buffer;
            write_bytes = &r->bytes_write;
        } else {
            recv_action = "client read: proxying and reading from client";
            send_action = "client read: proxying and sending to upstream";
            src = c;
            dst = r->upstream->peer.connection;
            b = r->buf;
            read_bytes = &r->bytes_read;
        }

    } else {
        if (ev->write) {
            recv_action = "upstream write: proxying and reading from client";
            send_action = "upstream write: proxying and sending to upstream";
            src = r->connection;
            dst = c;
            b = r->buf;
            read_bytes = &r->bytes_read;
        } else {
            recv_action = "upstream read: proxying and reading from upstream";
            send_action = "upstream read: proxying and sending to client";
            src = c;
            dst = r->connection;
            b = &r->upstream->buffer;
            write_bytes = &r->bytes_write;
        }
    }

    do_write = ev->write ? 1 : 0;

#if (NGX_TCP_SSL)
    /* SSL Need this */
    if (r->connection->ssl) {
        first_read = 1;
    }
#else
    first_read = 0;
#endif

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "tcp proxy handler: %d, #%d > #%d, time:%ui",
                   do_write, src->fd, dst->fd, ngx_current_msec);

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                n = dst->send(dst, b->pos, size);
                err = ngx_socket_errno;

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                               "tcp proxy handler send:%d,(%s)", n, b->pos);

				if (n == NGX_ERROR) {
					ngx_log_error(NGX_LOG_ERR, c->log, err, "proxy send error");
					ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
					return;
				}

                if (n > 0) {
                    b->pos += n;

                    if (write_bytes) {
                        *write_bytes += n;
                    }

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size) {
            if (src->read->ready || first_read) { 

                first_read = 0;
                c->log->action = recv_action;

                n = src->recv(src, b->last, size);
                err = ngx_socket_errno;

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                               "tcp proxy handler recv:%d,(%s)", n, b->last);

                if (n == NGX_AGAIN || n == 0) {
                    break;
                }

                if (n > 0) {
                    do_write = 1;
                    b->last += n;

                    if (read_bytes) {
                        *read_bytes += n;
                    }

                    continue;
                }

                if (n == NGX_ERROR) {
                    src->read->eof = 1;
                }
            }
        }

        break;
    }

    c->log->action = "nginx tcp proxying";

    if ((r->connection->read->eof && r->buf->pos == r->buf->last)
            || (r->upstream->peer.connection->read->eof
                && r->upstream->buffer.pos == r->upstream->buffer.last)
            || (r->connection->read->eof
                && r->upstream->peer.connection->read->eof))
    {
        action = c->log->action;
        c->log->action = NULL;
        ngx_log_error(NGX_LOG_DEBUG_HTTP, c->log, 0, "proxied session done");
        c->log->action = action;

        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_handle_read_event(dst->read, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_handle_write_event(src->write, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_handle_read_event(src->read, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (c == r->connection) {
        ngx_add_timer(c->read, r->upstream->conf->timeout);
    }

    if (c == r->upstream->peer.connection) {
        if (ev->write) {
            ngx_add_timer(c->write, r->upstream->conf->send_timeout);
        } else {
            ngx_add_timer(c->read, r->upstream->conf->read_timeout);
        }
    }

    return;
}
#endif

static void
ngx_http_tcp_upstream_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http tcp upstream dummy handler");

	return;
}

