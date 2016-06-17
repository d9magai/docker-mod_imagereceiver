#include <vector>
#include <string>
#include <stdexcept>
#include <exception>
#include <httpd.h>
#include <http_protocol.h>
#include <http_log.h>
#include <apr_strings.h>
#include <apreq2/apreq_util.h>
#include <apreq2/apreq_module_apache2.h>

extern "C" module AP_MODULE_DECLARE_DATA imagereceiver_module;

APLOG_USE_MODULE (imagereceiver);

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

module AP_MODULE_DECLARE_DATA imagereceiver_module = { STANDARD20_MODULE_STUFF, NULL, /* create per-dir config structures */
NULL, /* merge  per-dir    config structures */
NULL, /* create per-server config structures */
NULL, /* merge  per-server config structures */
NULL, /* table of config file commands */
imagereceiver_register_hooks /* register hooks */
};

