#include <vector>
#include <opencv2/opencv.hpp>
#include <httpd.h>
#include <http_protocol.h>
#include <http_log.h>
#include <apr_strings.h>
#include <apreq2/apreq_util.h>
#include <apreq2/apreq_module_apache2.h>
#include <json-c/json.h>

extern "C" module AP_MODULE_DECLARE_DATA imagereceiver_module;

APLOG_USE_MODULE (imagereceiver);

static int imagereceiver_handler(request_rec *r) {

    if (strcmp(r->handler, "imagereceiver")) {
        return DECLINED;
    }

    apreq_param_t *param = apreq_body_get(apreq_handle_apache2(r), "image");
    if (param == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APLOG_MODULE_INDEX, r, "no such param");
        return HTTP_BAD_REQUEST;
    } else if (param->upload == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APLOG_MODULE_INDEX, r, "not upload");
        return HTTP_BAD_REQUEST;
    }
    std::string contentType = apr_table_get(param->info, "Content-Type");
    std::string type = contentType.substr(0, contentType.find('/'));
    if (type != "image") {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APLOG_MODULE_INDEX, r, "is not image");
        return HTTP_BAD_REQUEST;
    }

    apr_bucket_brigade *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apreq_brigade_copy(bb, param->upload);
    std::vector<char> vec;
    for (apr_bucket *e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb); e = APR_BUCKET_NEXT(e)) {
        const char *data;
        apr_size_t len;
        if (apr_bucket_read(e, &data, &len, APR_BLOCK_READ) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APLOG_MODULE_INDEX, r, "failed to read bucket");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        const char *dup_data = apr_pstrmemdup(r->pool, data, len);
        vec.insert(vec.end(), dup_data, dup_data + len);
        apr_bucket_delete(e);
    }
    cv::Mat image = cv::imdecode(cv::Mat(vec), CV_LOAD_IMAGE_COLOR);

    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "rows", json_object_new_string(std::to_string(image.rows).c_str()));
    json_object_object_add(jobj, "cols", json_object_new_string(std::to_string(image.cols).c_str()));
    ap_set_content_type(r, "application/json");
    ap_rprintf(r, json_object_to_json_string(jobj));

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

