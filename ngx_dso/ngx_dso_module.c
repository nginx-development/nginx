/*
 * =============================================================================
 *
 *       Filename:  ngx_dso_module.c
 *    Description:  ngx_dso_module
 *
 *        Version:  1.0
 *        Created:  2013-08-06 11:38:45
 *       Revision:  none
 *         Author:  mayfengcrazy@163.com, 
 *        Company:  CUN
 *
 * =============================================================================
 */



#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>
#include <dlfcn.h>


#define NGX_MAX_DSO_MODULES	64;	

typedef struct {
    ngx_str_t     name;
    ngx_str_t     file;
    ngx_str_t     position;
    void         *handle;
    ngx_module_t *module;
} ngx_dso_module_t;


typedef struct {
    ngx_array_t  	*modules;
	ngx_uint_t	 	ngx_max_dso_module;
	ngx_module_t 	**ngx_modules;
	u_char 			**ngx_module_names;
	void         	****conf_ctx;
} ngx_dso_conf_ctx_t;

static void *ngx_dso_create_conf(ngx_cycle_t *cycle);
static char *ngx_dso_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_dso_parse(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static char *ngx_dso_load(ngx_conf_t *cf);
static void ngx_dso_cleanup(void *data);
static ngx_int_t ngx_dso_check_duplicated(ngx_conf_t *cf,
    ngx_array_t *modules, ngx_str_t *name, ngx_str_t *file);
static ngx_int_t ngx_dso_find_postion(ngx_dso_conf_ctx_t *ctx,
    ngx_str_t module_name);
static ngx_int_t ngx_is_dynamic_module(ngx_conf_t *cf, u_char *name,
    ngx_uint_t *major_version, ngx_uint_t *minor_version);
#ifdef NGX_DSO_DEBUG
static void ngx_dso_show_modules(ngx_cycle_t *cycle);
#endif

static ngx_command_t  ngx_dso_module_commands[] = {

    { ngx_string("dso"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_dso_block,
      0,
      0,
      NULL },

    ngx_null_command
};

static ngx_core_module_t  ngx_dso_module_ctx = {
    ngx_string("dso"),
    ngx_dso_create_conf,
    NULL,
};


extern ngx_module_t *_ngx_modules[];
extern u_char *_ngx_module_names[];
extern ngx_module_t **ngx_modules;
extern u_char **ngx_module_names;

const ngx_module_t ** const ngx_static_modules = 
							(const ngx_module_t **const)_ngx_modules;
const u_char ** const ngx_static_module_names =
							(const u_char **const)_ngx_module_names;


ngx_module_t  ngx_dso_module = {
    NGX_MODULE_V1,
    &ngx_dso_module_ctx,                   /* module context */
    ngx_dso_module_commands,               /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_dso_create_conf(ngx_cycle_t *cycle)
{
    ngx_dso_conf_ctx_t  *ctx = NULL;
    ngx_pool_cleanup_t  *cln = NULL;
	ngx_int_t			ngx_dso_max_module = 0;

    ctx = ngx_pcalloc(cycle->pool, sizeof(ngx_dso_conf_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

	ctx->ngx_max_dso_module = NGX_MAX_DSO_MODULES;
	ngx_dso_max_module = ctx->ngx_max_dso_module + ngx_max_module;

   	ctx->ngx_modules = (ngx_module_t **)ngx_pcalloc(cycle->pool, 
				sizeof(ngx_module_t *) * ngx_dso_max_module);
   	if (ctx->ngx_modules == NULL) {
       	return NULL;
   	}

	ngx_memset(ctx->ngx_modules, 0, ngx_dso_max_module);
	ngx_memcpy(ctx->ngx_modules, ngx_modules,
				sizeof(ngx_module_t *) * ngx_max_module);
	ngx_modules = ctx->ngx_modules;
   	
	ctx->ngx_module_names = ngx_pcalloc(cycle->pool, 
				sizeof(ngx_module_t *) * ngx_dso_max_module);
   	if (ctx->ngx_module_names == NULL) {
       	return NULL;
   	}

	ngx_memset(ctx->ngx_module_names, 0, ngx_dso_max_module);
	ngx_memcpy(ctx->ngx_module_names, ngx_module_names,
				sizeof(ngx_module_t *) * ngx_max_module);
	ngx_module_names = ctx->ngx_module_names;

   	ctx->conf_ctx = ngx_pcalloc(cycle->pool, 
				sizeof(void *) * ngx_dso_max_module);
   	if (ctx->conf_ctx == NULL) {
       	return NULL;
   	}

	ngx_memset(ctx->conf_ctx, 0, ngx_dso_max_module);
	ngx_memcpy(ctx->conf_ctx, cycle->conf_ctx,
        		sizeof(ngx_module_t *) * ngx_max_module);
	
	cycle->conf_ctx = ctx->conf_ctx;

    cln = ngx_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_dso_cleanup;
    cln->data = cycle;

#ifdef NGX_DSO_DEBUG
	ngx_dso_show_modules(cycle);
#endif

    return ctx;
}


static char *
ngx_dso_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                *rv = NULL;
    ngx_conf_t           pcf;
    ngx_dso_conf_ctx_t  *ctx = NULL;

    ctx = (ngx_dso_conf_ctx_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                              ngx_dso_module);
    if (ctx->modules != NULL) {
        return "is duplicate";
    }

    ctx->modules = ngx_array_create(cf->pool, 50, sizeof(ngx_dso_module_t));
    if (ctx->modules == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_dso_conf_ctx_t **) conf = ctx;

#ifdef NGX_DSO_DEBUG
	ngx_dso_show_modules(cf->cycle);
#endif

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_CORE_MODULE;
    cf->handler = ngx_dso_parse;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);
    if (rv != NGX_CONF_OK) {
        goto failed;
    }

    rv = ngx_dso_load(cf);
    if (rv != NGX_CONF_OK) {
        goto failed;
    }

    *cf = pcf;

#ifdef NGX_DSO_DEBUG
	ngx_dso_show_modules(cf->cycle);
#endif
    return NGX_CONF_OK;

failed:
    *cf = pcf;
    return rv;
}


static void
ngx_dso_cleanup(void *data)
{
    ngx_uint_t           i = 0;
    ngx_cycle_t       	*cycle = data;
    ngx_dso_module_t    *dm = NULL;
    ngx_dso_conf_ctx_t  *ctx = NULL;

    if (cycle->conf_ctx) {

        ctx = (ngx_dso_conf_ctx_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_dso_module);

        if (ctx != NULL && ctx->modules != NULL) {
            dm = ctx->modules->elts;

            for (i = 0; i < ctx->modules->nelts; i++) {
                if (dm[i].name.len == 0 || dm[i].handle == NULL) {
                    continue;
                }

                dlclose(dm[i].handle);
            }
        }

		ngx_modules = (ngx_module_t **) ngx_static_modules;
		ngx_module_names = (u_char **) ngx_static_module_names;
    }
}


static ngx_int_t
ngx_dso_check_duplicated(ngx_conf_t *cf, ngx_array_t *modules,
    ngx_str_t *name, ngx_str_t *file)
{
    size_t              len = 0;
    ngx_uint_t          i = 0;
	ngx_uint_t		 	major_version = 0, minor_version = 0;
	u_char 				**ngx_dso_module_names = NULL;
	ngx_dso_conf_ctx_t 	*ctx = NULL;

	ctx = cf->ctx;
	ngx_dso_module_names = ctx->ngx_module_names ;

    for (i = 0; ngx_static_module_names[i]; i++) {
        len = ngx_strlen(ngx_static_module_names[i]);

        if (len == name->len
           && ngx_strncmp(ngx_static_module_names[i], name->data, name->len) == 0)
        {

			ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
					"module %V is already statically loaded, "
					"skipping", name);

			return NGX_DECLINED;
        }
    }

	if (ngx_is_dynamic_module(cf, name->data,
				&major_version, &minor_version) == NGX_OK)
	{
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
				"module \"%V/%V\" is already dynamically "
				"loaded, skipping", file, name);
		return NGX_DECLINED;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_dso_open(ngx_conf_t *cf, ngx_dso_module_t *dm)
{
    ngx_str_t name, file;

    name = dm->name;
    file = dm->file;

    dm->handle = dlopen((const char*)file.data, RTLD_NOW | RTLD_GLOBAL);
    if (dm->handle == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
                           "load module \"%V\" failed (%s)",
                           &file, dlerror());
        return NGX_ERROR;
    }

    dm->module = dlsym(dm->handle, (const char *) name.data);
    if (dm->module == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
                           "can't locate symbol in module \"%V\"", &name);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_dso_insert_module(ngx_dso_conf_ctx_t *ctx, ngx_dso_module_t *dm, ngx_int_t flag_postion)
{
    u_char        *n = NULL;
	u_char		  *name = NULL;
    ngx_uint_t    i = 0;
    ngx_module_t  *m = NULL;
	ngx_module_t  *module = NULL;
	ngx_module_t  **ngx_dso_modules = NULL;
	u_char		  **ngx_dso_module_names = NULL;
	void 		  *c = NULL;
	void          *conf_ctx = NULL; 
	void 		  ****ngx_dso_conf_ctx = NULL;

    module = dm->module;
    name = dm->name.data;

	ngx_dso_modules = ctx->ngx_modules;
	ngx_dso_module_names = ctx->ngx_module_names;
	ngx_dso_conf_ctx = ctx->conf_ctx;

    /* start to insert */
	flag_postion ++;
    for (i = flag_postion; ngx_dso_modules[i]; i++) {
        m = ngx_dso_modules[i];
        n = ngx_dso_module_names[i];
		c = ngx_dso_conf_ctx[i];

        ngx_dso_modules[i] = module;
        ngx_dso_module_names[i] = name;
		ngx_dso_conf_ctx[i] = conf_ctx;

		module->index = i;
        module = m;
        name = n;
		conf_ctx = c;
    }

    ngx_dso_modules[i] = module;
    ngx_dso_module_names[i] = name;
    ngx_dso_modules[i]->index = i;

    return NGX_CONF_OK;
}


static char *
ngx_dso_save(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t            rc = NGX_OK, len = 0;
    ngx_str_t           *value = NULL, file, name, position;
    ngx_dso_module_t    *dm = NULL;
    ngx_dso_conf_ctx_t  *ctx = NULL;
	u_char				*filename = NULL;
	ngx_uint_t			i = 0;

    ctx = cf->ctx;
    value = cf->args->elts;
	ngx_memzero(&file, sizeof(file));
	ngx_memzero(&position, sizeof(position));

	if (ctx->modules->nelts >= ctx->ngx_max_dso_module) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"module \"%V\" can not be loaded, "
				"because the dso module limit (%ui) is reached.",
				&value[1], ctx->ngx_max_dso_module);
		goto err;
	}

	name = value[1];

	for (i = 2; i < cf->args->nelts; i++){
		if (ngx_strcmp(value[i].data, "after") == 0){

			i++;
			if (i >= cf->args->nelts){
				goto err;
			}

			if (position.len != 0){
				goto err;
			}

			position = value[i];
			continue;
		}

		if (file.len != 0){
			goto err;
		}

		file = value[i];
	}


	if (file.len == 0){
	
		len = strlen("modules/*.so") + name.len;
		filename = ngx_palloc(cf->pool, len);
		if (filename == NULL){
			goto err;
		}

		ngx_memzero(filename,len);
		ngx_snprintf(filename, len, "modules/%s.so", name.data);
		file.data = filename;
		file.len = ngx_strlen(filename);
	}

	if (file.data[0] != '/'){
		rc = ngx_conf_full_name(cf->cycle, &file, 0);
		if(rc){
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"[%V] config full name error!",&name);
			goto err;
		}
	}
	
    rc = ngx_dso_check_duplicated(cf, ctx->modules,
                                  &name, &file);
    if (rc != NGX_OK) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"dso module[%V] duplicated!", &name);
        return NGX_CONF_OK;	//ignore dso duplicated module errors
    }

    dm = ngx_array_push(ctx->modules);
    if (dm == NULL) {
        return NGX_CONF_ERROR;
    }

    dm->name = name;
    dm->file = file;
    dm->position = position;
    dm->handle = NULL;

#ifdef NGX_DSO_DEBUG
	printf("name:%s,file:%s,position:%s.\n",name.data,file.data,position.data);
#endif

    return NGX_CONF_OK;
err:
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"dso module[%V] config error!", &value[1]);
	return NGX_CONF_ERROR;
}


static char *
ngx_dso_load(ngx_conf_t *cf)
{
    char                *rv = NULL;
    ngx_int_t            postion = 0;
    ngx_uint_t           i = 0;
    ngx_dso_module_t    *dm = NULL;
    ngx_dso_conf_ctx_t  *ctx = NULL;

    ctx = cf->ctx;
    dm = ctx->modules->elts;

    for (i = 0; i < ctx->modules->nelts; i++) {

        if (ngx_dso_open(cf, &dm[i]) == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        if (dm[i].module->type == NGX_CORE_MODULE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "core modules can not be dynamically loaded");
            return NGX_CONF_ERROR;
        }

		dm[i].module->index = 0;
        postion = ngx_dso_find_postion(ctx, dm[i].position);
		if (postion == 0){
        	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "dso (%V) not find position!", &dm[i].position);
			return NGX_CONF_ERROR;
		}

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cf->log, 0,
                       "dso (%V) find postion (%i)", &dm[i].position, postion);

        rv = ngx_dso_insert_module(ctx, &dm[i], postion);
        if (rv == NGX_CONF_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dso failed to find position (%i)", postion);
            return rv;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_dso_parse(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_str_t           *value = NULL;

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "load") == 0) {

        if (cf->args->nelts < 2 || cf->args->nelts > 5 ) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid number of arguments "
                               "in \"load\" directive");
            return NGX_CONF_ERROR;
        }

        return ngx_dso_save(cf, dummy, conf);
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown directive \"%V\"", &value[0]);
    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_dso_find_postion(ngx_dso_conf_ctx_t *ctx, ngx_str_t module_name)
{
    size_t      len = 0;
    ngx_uint_t  i = 0;
	u_char		**ngx_dso_module_names = NULL;

	ngx_dso_module_names = ctx->ngx_module_names;

	if (module_name.len == 0){
		for (i = 1; ngx_dso_module_names[i]; i++){}
		return i - 1;
	}

    for (i = 1; ngx_dso_module_names[i]; i++) {
        len = ngx_strlen(ngx_dso_module_names[i]);
       
		if (len == module_name.len
           && ngx_strncmp(ngx_module_names[i],
                          module_name.data, len) == 0)
        {
            return i;
        }
	}

	return 0;
}


static ngx_int_t
ngx_is_dynamic_module(ngx_conf_t *cf, u_char *name,
    ngx_uint_t *major_version, ngx_uint_t *minor_version)
{
    size_t               len = 0;
    ngx_uint_t           i = 0;
    ngx_dso_module_t    *dm = NULL; 
    ngx_dso_conf_ctx_t  *ctx = NULL;

    ctx = (ngx_dso_conf_ctx_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                              ngx_dso_module);

    if (ctx == NULL || ctx->modules == NULL) {
        return NGX_DECLINED;
    }

    dm = ctx->modules->elts;
    len = ngx_strlen(name);

    for (i = 0; i < ctx->modules->nelts; i++) {
        if (dm[i].name.len == 0) {
            continue;
        }

        if (len == dm[i].name.len &&
            ngx_strncmp(dm[i].name.data, name, dm[i].name.len) == 0)
        {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

#ifdef NGX_DSO_DEBUG
static void 
ngx_dso_show_modules(ngx_cycle_t *cycle)
{
	ngx_int_t i = 0;

	for (i = 0; ngx_modules[i]; i++){
		printf("module_name:%s,index:%d,module_index:%d,conf_ctx:%p.\n",
			ngx_module_names[i],i,ngx_modules[i]->index,
			cycle->conf_ctx[ngx_modules[i]->index]);
	}

	return;
}
#endif


