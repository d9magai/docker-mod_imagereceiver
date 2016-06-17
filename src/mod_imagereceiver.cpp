#include <vector>
#include <string>
#include <stdexcept>
#include <exception>
#include <httpd.h>
#include "http_config.h"
#include <http_protocol.h>
#include <http_log.h>
#include <apr_strings.h>
#include "mod_imagereceiver.h"

extern "C" module AP_MODULE_DECLARE_DATA imagereceiver_module;

APLOG_USE_MODULE (imagereceiver);

/* 設定情報の生成・初期化(追加) */
static void *create_per_server_config(apr_pool_t *pool, server_rec *s)
{
    struct Credential *cfg = (struct Credential*)(apr_pcalloc(pool, sizeof(struct Credential)));
    return cfg;
}

class bad_request: public std::runtime_error {
public:
    explicit bad_request(const std::string& s) :
            std::runtime_error(s) {
    }
};

class internal_server_error: public std::runtime_error {
public:
    explicit internal_server_error(const std::string& s) :
            std::runtime_error(s) {
    }
};

static int imagereceiver_handler(request_rec *r) {

    if (strcmp(r->handler, "imagereceiver")) {
        return DECLINED;
    }

    try {

    } catch (bad_request& e) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APLOG_MODULE_INDEX, r, e.what());
        return HTTP_BAD_REQUEST;
    } catch (internal_server_error& e) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APLOG_MODULE_INDEX, r, e.what());
        return HTTP_INTERNAL_SERVER_ERROR;
    } catch (std::exception& e) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APLOG_MODULE_INDEX, r, e.what());
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

static void imagereceiver_register_hooks(apr_pool_t *p) {
    ap_hook_handler(imagereceiver_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


static const char *set_accesskeyid(cmd_parms *parms, void *mconfig, const char *arg)
{
    if (strlen(arg) == 0) {
        return "AWS_ACCESS_KEY_ID argument must be a string";
    }

    struct Credential *cfg = (struct Credential*)(ap_get_module_config(parms->server->module_config, &imagereceiver_module));
    cfg->accesskeyid = arg;
    return NULL;
}

static const char *set_secretaccesskey(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    if (strlen(arg) == 0) {
        return "AWS_SECRET_ACCESS_KEY argument must be a string";
    }

    struct Credential *cfg = (struct Credential*)(ap_get_module_config(parms->server->module_config, &imagereceiver_module));
    cfg->secretaccesskey = arg;
    return NULL;
}

static const char *set_sha256secretkey(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    if (strlen(arg) == 0) {
        return "SHA256_SECRET_KEY argument must be a string";
    }

    struct Credential *cfg = (struct Credential*)(ap_get_module_config(parms->server->module_config, &imagereceiver_module));
    cfg->sha256secretkey = arg;
    return NULL;
}

/* 設定情報フック定義(追加) */
static const command_rec auth_s3req_cmds[] =
    {
        {
        "AWS_ACCESS_KEY_ID", set_accesskeyid, 0, RSRC_CONF, TAKE1, "aws access key id."
        },
        {
        "AWS_SECRET_ACCESS_KEY", set_secretaccesskey, 0, RSRC_CONF, TAKE1, "aws secret access key."
        },
        {
        "SHA256_SECRET_KEY", set_sha256secretkey, 0, RSRC_CONF, TAKE1, "sha256 secret key."
        },
        {
        0
        },
    };

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA imagereceiver_module = {
        STANDARD20_MODULE_STUFF,
        NULL,                     /* create per-dir    config structures */
        NULL,                     /* merge  per-dir    config structures */
        create_per_server_config, /* create per-server config structures */
        NULL,                     /* merge  per-server config structures */
        auth_s3req_cmds,          /* table of config file commands       */
        imagereceiver_register_hooks            /* register hooks                      */
};
