#include <vector>
#include <exception>
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

apreq_param_t *get_validated_post_param(request_rec *r, const char *name) {

    apreq_param_t *param = apreq_body_get(apreq_handle_apache2(r), name);
    if (param == NULL) {
        throw bad_request("no such param");
    } else if (param->upload == NULL) {
        throw bad_request("not upload");
    }
    std::string contentType = apr_table_get(param->info, "Content-Type");
    std::string type = contentType.substr(0, contentType.find('/'));
    if (type != "image") {
        throw bad_request("is not image");
    }

    return param;
}

cv::Mat convert_to_mat(request_rec *r, apr_bucket_brigade *upload) {

    apr_bucket_brigade *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apreq_brigade_copy(bb, upload);
    std::vector<char> vec;
    for (apr_bucket *e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb); e = APR_BUCKET_NEXT(e)) {
        const char *data;
        apr_size_t len;
        if (apr_bucket_read(e, &data, &len, APR_BLOCK_READ) != APR_SUCCESS) {
            throw internal_server_error("failed to read bucket");
        }
        const char *dup_data = apr_pstrmemdup(r->pool, data, len);
        vec.insert(vec.end(), dup_data, dup_data + len);
        apr_bucket_delete(e);
    }

    cv::Mat ret = cv::imdecode(cv::Mat(vec), CV_LOAD_IMAGE_COLOR);
    if (ret.data == NULL) {
        throw internal_server_error("buffer is too short or contains invalid data");
    }
    return ret;
}

const char *get_json_string(cv::Mat image) {

    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "rows", json_object_new_string(std::to_string(image.rows).c_str()));
    json_object_object_add(jobj, "cols", json_object_new_string(std::to_string(image.cols).c_str()));
    return json_object_to_json_string(jobj);
}

std::string encode_mat_to_string(cv::Mat image) {

    std::vector<int> p;
    p.push_back(CV_IMWRITE_JPEG_QUALITY);
    p.push_back(100);
    std::vector<unsigned char> buf;
    cv::imencode(".jpg", image, buf, p);
    return std::string(buf.begin(), buf.end());
}

static int imagereceiver_handler(request_rec *r) {

    if (strcmp(r->handler, "imagereceiver")) {
        return DECLINED;
    }

    try {
        apreq_param_t *param = get_validated_post_param(r, "image");
        cv::Mat image = convert_to_mat(r, param->upload);
        std::string data = encode_mat_to_string(image);
        
        apr_bucket *bkt = apr_bucket_pool_create(data.c_str(), data.length(), r->pool, r->connection->bucket_alloc);
        apr_bucket_brigade *bucket_brigate = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bucket_brigate, bkt);
        ap_set_content_type(r, "image/jpg");
        ap_set_content_length(r, data.length());
        ap_pass_brigade(r->output_filters, bucket_brigate);

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

