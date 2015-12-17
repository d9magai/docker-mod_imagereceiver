#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/utils/StringUtils.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <cstdlib>
#include <vector>
#include <exception>
#include <opencv2/opencv.hpp>
#include <httpd.h>
#include <http_protocol.h>
#include <http_log.h>
#include <apr_strings.h>
#include <apreq2/apreq_util.h>
#include <apreq2/apreq_module_apache2.h>

extern "C" module AP_MODULE_DECLARE_DATA imagereceiver_module;

APLOG_USE_MODULE (imagereceiver);

using namespace Aws::Auth;
using namespace Aws::Http;
using namespace Aws::Client;
using namespace Aws::S3;
using namespace Aws::S3::Model;
using namespace Aws::Utils;

/* モジュール設定情報(追加) */
struct mytest_config {
    const char  *message;
    cv::Mat mat;
    std::shared_ptr<Aws::S3::S3Client> s3Client;
} mytest_config;

/* 設定情報の生成・初期化(追加) */
static void * create_per_dir_config (apr_pool_t *pool, char *arg)
{

    const char* ALLOCATION_TAG = "ALLOCATION_TAG";
    putenv("AWS_ACCESS_KEY_ID=XXXXXXXXXXXXXXXXXXXXX");
    putenv("AWS_SECRET_KEY_ID=XXXXXXXXXXXXXXXXXXXXXXXXXXXX");

    void * buf = apr_pcalloc(pool, sizeof(mytest_config));
    struct mytest_config *cfg = (struct mytest_config*)buf;
    // default value
    cfg->message    = "The sample page by mod_mytest.c";
    cfg->mat = cv::Mat::ones(100, 100, CV_8U) * 100;

    Aws::Client::ClientConfiguration config;
    config.scheme = Aws::Http::Scheme::HTTPS;
    config.connectTimeoutMs = 30000;
    config.requestTimeoutMs = 30000;
    config.region = Aws::Region::AP_NORTHEAST_1;
    cfg->s3Client = Aws::MakeShared<S3Client>(ALLOCATION_TAG, Aws::MakeShared<DefaultAWSCredentialsProviderChain>(ALLOCATION_TAG), config);

    return buf;
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

cv::Mat bb2Mat(request_rec *r, apr_bucket_brigade *upload) {

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

cv::Mat detect_face(cv::Mat image, const std::string cascade_filename) {

    cv::Mat gray;
    cv::cvtColor(image, gray, cv::COLOR_BGRA2GRAY);
    cv::CascadeClassifier cascade;
    cascade.load(cascade_filename);
    std::vector<cv::Rect> faces;
    cascade.detectMultiScale(gray, faces);

    cv::Mat ret = image;
    for (auto face : faces) {
        cv::rectangle(ret, face, CV_RGB(255, 0, 0), 3);
    }
    return ret;
}

std::string encodeMat(cv::Mat image) {

    std::vector<int> p { CV_IMWRITE_JPEG_QUALITY, 100 };
    std::vector<unsigned char> buf;
    cv::imencode(".jpg", image, buf, p);
    return std::string(buf.begin(), buf.end());
}

static int imagereceiver_handler(request_rec *r) {

    if (strcmp(r->handler, "imagereceiver")) {
        return DECLINED;
    }

    try {
        struct mytest_config *cfg = static_cast<struct mytest_config*>ap_get_module_config(r->per_dir_config, &imagereceiver_module);
       
        Aws::S3::Model::GetObjectRequest getObjectRequest;
        getObjectRequest.SetBucket("mybucket");
        getObjectRequest.SetKey("path/to/img.JPG");
        auto getObjectOutcome = cfg->s3Client->GetObject(getObjectRequest);
        if (!getObjectOutcome.IsSuccess()) {
            std::cerr << "File download failed from s3 with error " << getObjectOutcome.GetError().GetMessage() << std::endl;
            exit(1);
        }
        std::stringstream ss;
        ss << getObjectOutcome.GetResult().GetBody().rdbuf();
        std::string str = ss.str();
        std::vector<char> vec(str.begin(), str.end());
        cv::Mat img = cv::imdecode(cv::Mat(vec), CV_LOAD_IMAGE_COLOR);
        std::string data = encodeMat(img);
        //std::string data = encodeMat(cfg->mat);
       
        apr_bucket *bucket = apr_bucket_pool_create(data.c_str(), data.length(), r->pool, r->connection->bucket_alloc);
        apr_bucket_brigade *bucket_brigate = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bucket_brigate, bucket);
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

module AP_MODULE_DECLARE_DATA imagereceiver_module = {
    STANDARD20_MODULE_STUFF,
    create_per_dir_config,       /* create per-dir config structures */
    NULL,                        /* merge  per-dir    config structures */
    NULL,                        /* create per-server config structures */
    NULL,                        /* merge  per-server config structures */
    NULL,                        /* table of config file commands */
    imagereceiver_register_hooks /* register hooks */
};

