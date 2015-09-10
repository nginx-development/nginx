/*
 * =============================================================================
 *
 *       Filename:  ngx_http_upstream_api.c
 *    Description:  upstream apis
 *
 *        Version:  1.0
 *        Created:  2014-03-18 16:27:09
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

static void
ngx_downstream_read_handler(ngx_http_request_t *r);
static void
ngx_upstream_process_header(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);
static ngx_int_t
ngx_upstream_non_buffered_filter_init(void *data);
static ngx_int_t
ngx_upstream_non_buffered_filter(void *data, ssize_t bytes);
static void
ngx_downstream_write_handler(ngx_http_request_t *r);
static void
ngx_upstream_write_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u);

void 
ngx_upstream_init_transfer(ngx_http_request_t *r, 
		ngx_http_upstream_t *u)
{
	ngx_connection_t  *c = NULL, *pc = NULL;

	c = r->connection;
	pc = u->peer.connection;

	c->sent = 0;	//flow statistic start

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
			"upstream init transfer");

	if (u->buffer.start == NULL) {
		u->buffer.start = ngx_palloc(r->pool, u->conf->buffer_size);
		if (u->buffer.start == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"alloc error");
			ngx_http_upstream_finalize_request(r, u,
					NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		u->buffer.pos = u->buffer.start;
		u->buffer.last = u->buffer.start;
		u->buffer.end = u->buffer.last + u->conf->buffer_size;
		u->buffer.temporary = 1;
	}

	c->read->handler = ngx_http_upstream_proxy_handler;
	c->write->handler = ngx_http_upstream_proxy_handler;

	u->read_event_handler = ngx_upstream_process_header;
	if (pc->read->timer_set){
		ngx_del_timer(pc->read);
	}

	pc->read->handler = ngx_http_upstream_proxy_handler;
	pc->write->handler = ngx_http_upstream_proxy_handler;

	ngx_add_timer(pc->read, u->conf->timeout);

	if (ngx_handle_read_event(pc->read, 0) != NGX_OK){

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"upstream init transfer: handle read event error");
		ngx_http_upstream_finalize_request(r, u,
				NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	r->write_event_handler = ngx_downstream_write_handler;

	if(u->downstream){

		ngx_http_downstream_init(r, u);

	}else{

		if (r->buf == NULL) {
			r->buf = ngx_create_temp_buf(r->pool, u->conf->buffer_size);
			if (r->buf == NULL) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"alloc error");

				ngx_http_upstream_finalize_request(r, u,
						NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}
		}

		r->read_event_handler = ngx_downstream_read_handler;
		u->write_event_handler = ngx_upstream_write_handler;

		if (c->read->timer_set){
			ngx_del_timer(c->read);
		}

		ngx_add_timer(c->read, u->conf->timeout);
		if (ngx_handle_read_event(c->read, 0) != NGX_OK){

			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"handle read event error");
			ngx_http_upstream_finalize_request(r, u,
					NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}

	if (pc->read->ready){
		ngx_http_upstream_read_handler(r);
	}

	if (c->read->ready){
		ngx_http_downstream_read_handler(r);
	}

	return;
}

/* NOTICE: not ready to use */
static void
ngx_downstream_read_handler(ngx_http_request_t *r)
{
	size_t					size = 0;
	ssize_t					n = 0;
	ngx_buf_t				*b = NULL;
	ngx_err_t				err;
	ngx_connection_t		*c = NULL;
	ngx_http_upstream_t		*u = NULL;
	ngx_usersession_t		*sess = NULL;

	c = r->connection;
	c->log->action = "read from downstream";

	u = r->upstream;
	b = r->buf;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"read downstream handler");

	sess = ngx_http_request_usersession_curr(r);
	if (NULL == sess) {
		ngx_http_upstream_proxy_finalize_request(r, u, 0);
		return;
	}

	sess->last_access = ngx_time();

	for ( ;; ) {

		size = b->end - b->last;

		if (size) {
			if (c->read->ready) { 

				n = c->recv(c, b->last, size);
				err = ngx_socket_errno;

				ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						"downstream handler recv:%d,(%.*s)", n, n, b->last);

				if (n == NGX_AGAIN) {
					ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
							"downstream read eagain");
					return;
				}

				if (n == 0) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0,
							"downstream prematurely closed connection");
				}

				if (n == NGX_ERROR || n == 0) {
					ngx_log_error(NGX_LOG_ERR, c->log, 0,
							"downstream prematurely closed connection with error");
					ngx_http_upstream_proxy_finalize_request(r, u,
							NGX_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				if (n > 0) {
					b->last += n;

					ngx_atomic_fetch_add(&sess->up_flow, n);
					r->bytes_read += n;
					ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
							"downstream read bytes statistic:%i.", r->bytes_read);
					continue;
				}

				if (n == NGX_ERROR) {
					ngx_http_upstream_proxy_finalize_request(r, u,
							NGX_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}
			}
		}

		break;
	}

	n = b->last - b->pos;

	if (n) {
		b->last -= n;
	}

	ngx_http_upstream_write_handler(r);
	return;
}

static void
ngx_upstream_process_header(ngx_http_request_t *r, 
		ngx_http_upstream_t *u)
{
	ssize_t            n;
	ngx_int_t          rc;
	ngx_connection_t  *c = r->connection;

	c = u->peer.connection;
	c->log->action = "reading from upstream";

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"upstream process header");

	if (u->buffer.start == NULL) {

		u->buffer.start = ngx_palloc(r->pool, u->conf->buffer_size);
		if (u->buffer.start == NULL) {
			ngx_http_upstream_finalize_request(r, u,
					NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		u->buffer.pos = u->buffer.start;
		u->buffer.last = u->buffer.start;
		u->buffer.end = u->buffer.start + u->conf->buffer_size;
		u->buffer.temporary = 1;

		u->buffer.tag = u->output.tag;

	}

	for ( ;; ) {

		n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last);

		if (n == NGX_AGAIN) {
			ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
					"upstream read eagain");
			return;
		}

		if (n == NGX_ERROR || n == 0) {

			if (n == 0) {

				ngx_log_error(NGX_LOG_ERR, c->log, 0,
						"upstream closed connection");

				ngx_http_upstream_proxy_finalize_request(r, u,
						NGX_OK);
				return;
			}else{

				ngx_log_error(NGX_LOG_ERR, c->log, 0,
						"upstream prematurely closed connection with error");

				ngx_http_upstream_proxy_finalize_request(r, u,
						NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

		}

		u->buffer.last += n;

		rc = u->process_header(r);

		if (rc == NGX_AGAIN) {

			if (u->buffer.last == u->buffer.end) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
						"upstream read too big header");

				ngx_http_upstream_proxy_finalize_request(r, u,
						NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			continue;
		}

		break;
	}

	if (rc == NGX_ERROR) {
		ngx_http_upstream_proxy_finalize_request(r, u,
				NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	/* rc == NGX_OK */

	if (u->input_filter == NULL) {
		u->input_filter_init = ngx_upstream_non_buffered_filter_init;
		u->input_filter = ngx_upstream_non_buffered_filter;
		u->input_filter_ctx = r;
	}

	if (u->input_filter_init(u->input_filter_ctx) == NGX_ERROR) {
		ngx_http_upstream_proxy_finalize_request(r, u,
				NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	n = u->buffer.last - u->buffer.pos;

	if (n) {
		u->buffer.last -= n;

		u->state->response_length += n;

		if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
			ngx_http_upstream_proxy_finalize_request(r, u, NGX_ERROR);
			return;
		}
	}

	ngx_http_downstream_write_handler(r);
	return;
}

static ngx_int_t
ngx_upstream_non_buffered_filter_init(void *data)
{
	return NGX_OK;
}

#if 0
static ngx_int_t
ngx_downstream_non_buffered_filter(void *data, ssize_t bytes)
{
	ngx_http_request_t  *r = data;

	ngx_buf_t            *b;
	ngx_chain_t          *cl, **ll;

	for (cl = r->out_bufs, ll = &r->out_bufs; cl; cl = cl->next) {
		ll = &cl->next;
	}

	cl = ngx_chain_get_free_buf(r->pool, &r->free_bufs);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	*ll = cl;

	cl->buf->flush = 1;
	cl->buf->memory = 1;

	b = &r->buffer;

	cl->buf->pos = b->last;
	b->last += bytes;
	cl->buf->last = b->last;
	cl->buf->tag = r->output.tag;

	u->length -= bytes;

	return NGX_OK;
}
#endif

static ngx_int_t
ngx_upstream_non_buffered_filter(void *data, ssize_t bytes)
{
	ngx_http_request_t  *r = data;

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

	return NGX_OK;
}

ngx_int_t
ngx_http_downstream_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                      size;
    ngx_uint_t                 last, flush;
    ngx_chain_t               *cl, *ln, **ll, *chain;
    ngx_connection_t          *c;

    c = r->connection;

    if (c->error) {
        return NGX_ERROR;
    }

    size = 0;
    flush = 0;
    last = 0;
    ll = &r->out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = r->out; cl; cl = cl->next) {
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %z",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (ln = in; ln; ln = ln->next) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %z",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%d f:%d s:%O", last, flush, size);
    
	if (c->write->delayed) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    if (size == 0 && !(c->buffered & NGX_LOWLEVEL_BUFFERED)) {
        if (last || flush) {
            for (cl = r->out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                ngx_free_chain(r->pool, ln);
            }

            r->out = NULL;
            c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }

#if 0
	//debug use
	ngx_str_t	data;
	data.data = r->out->buf->pos;
	data.len = 20;
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
		"downstream write.%s,%d,data:%V.\n",__FILE__,__LINE__, &data);
#endif

    chain = c->send_chain(c, r->out, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        c->error = 1;
        return NGX_ERROR;
    }

    for (cl = r->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    r->out = chain;

    if (chain) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

    if ((c->buffered & NGX_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static void
ngx_downstream_write_handler(ngx_http_request_t *r)
{
	ngx_int_t				rc = 0;
	ngx_buf_t               *b = NULL;
	ngx_http_upstream_t 	*u = r->upstream;
	ngx_connection_t  		*c = r->connection, *pc = u->peer.connection;
	ngx_usersession_t		*sess = NULL;

	c = r->connection;
	c->log->action = "sending to downstream";

	u = r->upstream;
	b = &u->buffer;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"send to downstream");
	
	sess = ngx_http_request_usersession_curr(r);
	if (NULL == sess) {
		ngx_http_upstream_proxy_finalize_request(r, u, 0);
		return;
	}

	sess->last_access = ngx_time();

	for ( ;; ) {

		if (u->out_bufs || u->busy_bufs) {
			rc = ngx_http_downstream_write_filter(r, u->out_bufs);

			if (rc == NGX_ERROR) {
				ngx_http_upstream_proxy_finalize_request(r, u, 0);
				return;
			}


			ngx_atomic_fetch_add(&sess->down_flow, c->sent - r->bytes_write);
			r->bytes_write = c->sent;
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
					"downstream write bytes statistic:%i.", r->bytes_write);

			ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs,
					&u->out_bufs, u->output.tag);

			if(rc == NGX_AGAIN){

				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
						"downstream write eagain.\n");
				ngx_add_timer(c->write, u->conf->send_timeout);

				if(ngx_handle_write_event(c->write, 0) != NGX_OK){
					ngx_http_upstream_proxy_finalize_request(r, u, 
							NGX_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}
				
				pc->read->delayed = 1;

				return;
			}
		}
		if (u->busy_bufs == NULL) {
			b->pos = b->start;
			b->last = b->start;
		}
		break;
	}

	if (pc->read->delayed){
		pc->read->delayed = 0;

		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, 
				"downstream write delayed over.");
		ngx_http_upstream_proxy_handler(pc->read);		
	}

	return;
}


static void
ngx_upstream_write_handler(ngx_http_request_t *r, 
		ngx_http_upstream_t *u)
{
	size_t                    size = 0;
	ssize_t                   n = 0;
	ngx_buf_t                *b = NULL;
	ngx_err_t                 err;
	ngx_connection_t         *c = NULL, *pc = NULL;

	pc = r->connection;
	c->log->action = "send to upstream";

	c = r->upstream->peer.connection;
	b = r->buf;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"upstream write handler");

	for ( ;; ) {
		size = b->last - b->pos;

		if (size && c->write->ready) {
			n = c->send(c, b->pos, size);
			err = ngx_socket_errno;

			ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"upstream send:%d,(%.*s)", n, n, b->last);

			if (n == NGX_ERROR) {
				ngx_log_error(NGX_LOG_ERR, c->log, err, 
						"upstream send error");
				ngx_http_upstream_proxy_finalize_request(r, u,
						NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			if(n == NGX_EAGAIN){

				ngx_add_timer(c->write, u->conf->send_timeout);
				if(ngx_handle_write_event(c->write, 0) != NGX_OK){
					ngx_http_upstream_proxy_finalize_request(r, u, 
							NGX_HTTP_INTERNAL_SERVER_ERROR);
					return;
				}

				pc->read->delayed = 1;

				return;
			}

			if (n > 0) {
				b->pos += n;

				if (b->pos == b->last) {
					b->pos = b->start;
					b->last = b->start;
				}
			}
		}

		break;
	}


	if (pc->read->delayed){

		pc->read->delayed = 0;
		//ngx_http_upstream_read_handler(r);
		ngx_http_upstream_proxy_handler(pc->read);		
	}

	return;
}



