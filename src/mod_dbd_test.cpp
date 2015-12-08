#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_dbd.h"
#include "mod_dbd.h"
#include <string>

extern "C" module AP_MODULE_DECLARE_DATA dbd_test_module;

/* The sample content handler */
static int dbd_test_handler(request_rec *r)
{
    if (strcmp(r->handler, "dbd_test")) {
        return DECLINED;
    }
    r->content_type = "text/html";      

    ap_dbd_t *dbd = ap_dbd_acquire(r);
    const char *sql = "SELECT * FROM users;";
    apr_dbd_results_t *res = NULL;
    apr_status_t rv = apr_dbd_select(dbd->driver, r->pool, dbd->handle, &res, sql, 0);
    if (rv) {
        ap_rputs(std::to_string(rv).c_str(), r);
    }

    apr_dbd_row_t *row;
    while (apr_dbd_get_row(dbd->driver, r->pool, res, &row, 0) != -1) {
        ap_rputs(apr_dbd_get_entry(dbd->driver, row, 0), r);
        ap_rputs(apr_dbd_get_entry(dbd->driver, row, 1), r);
    }

    if (!r->header_only) {
        ap_rputs("The sample page from mod_dbd_test.c\n", r);
    }
    return OK;
}

static void dbd_test_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(dbd_test_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA dbd_test_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    dbd_test_register_hooks  /* register hooks                      */
};

