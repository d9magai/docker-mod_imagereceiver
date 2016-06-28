/* 
**  mod_helloworld.c -- Apache sample helloworld module
**  [Autogenerated via ``apxs -n helloworld -g'']
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i mod_helloworld.c
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /helloworld in as follows:
**
**    #   httpd.conf
**    LoadModule helloworld_module modules/mod_helloworld.so
**    <Location /helloworld>
**    SetHandler helloworld
**    </Location>
**
**  Then after restarting Apache via
**
**    $ apachectl restart
**
**  you immediately can request the URL /helloworld and watch for the
**  output of this module. This can be achieved for instance via:
**
**    $ lynx -mime_header http://localhost/helloworld 
**
**  The output should be similar to the following one:
**
**    HTTP/1.1 200 OK
**    Date: Tue, 31 Mar 1998 14:42:22 GMT
**    Server: Apache/1.3.4 (Unix)
**    Connection: close
**    Content-Type: text/html
**  
**    The sample page from mod_helloworld.c
*/ 

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"



extern module AP_MODULE_DECLARE_DATA helloworld_module;

typedef struct {
    char* hoge;
    char* huga;
} helloworld_server_config;

static void* create_helloworld_server_config(apr_pool_t* p, server_rec* s)
{
    helloworld_server_config* conf = apr_palloc(p, sizeof(helloworld_server_config));
    conf->hoge = apr_pstrdup(p, "hogehoge"); // デフォルト値を入れておくとか
    return conf;
}

static const char* helloworld_set_hoge(cmd_parms* cmd, void* dummy, const char* arg)
{
    helloworld_server_config* conf = ap_get_module_config(cmd->server->module_config, &(helloworld_module));
    conf->hoge = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/* The sample content handler */
static int helloworld_handler(request_rec *r)
{
    if (strcmp(r->handler, "helloworld")) {
        return DECLINED;
    }
    r->content_type = "text/html";      

    helloworld_server_config* conf = ap_get_module_config(r->server->module_config, &(helloworld_module));
    if (!r->header_only)
        //ap_rputs("The sample page from mod_helloworld.c\n", r);
        ap_rputs(conf->hoge, r);
    return OK;
}

/*
static const command_rec helloworld_cmds[] = {
    //AP_INIT_TAKE1("hoge", helloworld_set_hoge, NULL, OR_ALL, "help message for hoge"),
    {
    "HOGE", helloworld_set_hoge, 0, RSRC_CONF, TAKE1, "The timeout for connections to the REDIS server"
    },
    {NULL}
};
*/

static const command_rec helloworld_cmds[] =
    {
        AP_INIT_TAKE1("HOGE", helloworld_set_hoge, NULL, OR_ALL, "help message for hoge"),
        {
        0
        },
    };



static void helloworld_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(helloworld_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA helloworld_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    create_helloworld_server_config,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    helloworld_cmds,                  /* table of config file commands       */
    helloworld_register_hooks  /* register hooks                      */
};
