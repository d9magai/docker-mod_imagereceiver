#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/utils/StringUtils.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/GetObjectRequest.h>
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

void log_err(request_rec *r, const char *error_message) {

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s: query string is %s", error_message, r->args);
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

    std::stringstream iss;
    iss << r->args;
    std::string tmp;
    std::vector<std::string> res;
    std::map<std::string, std::string> map;
    while(getline(iss, tmp,'&')) {
        std::stringstream i(tmp);
        std::string t;
        std::vector<std::string> v;
        while(getline(i, t,'=')) {
            v.push_back(t);
        }
        map.insert(std::make_pair(v[0], v[1]));
    }

    try {
        struct Credential *crd = (struct Credential*)(ap_get_module_config(r->server->module_config, &imagereceiver_module));
        Aws::Client::ClientConfiguration config;
        config.scheme = Aws::Http::Scheme::HTTPS;
        config.connectTimeoutMs = 30000;
        config.requestTimeoutMs = 30000;
        config.region = Aws::Region::AP_NORTHEAST_1;

        Aws::StringStream ass;
        ass << crd->accesskeyid;
        Aws::String accesskeyid = ass.str();
        ass.str("");
        ass << crd->secretaccesskey;
        Aws::String secretaccesskey = ass.str();
        ass.str("");
        Aws::S3::S3Client s3Client(Aws::Auth::AWSCredentials(accesskeyid, secretaccesskey), config);

        Aws::S3::Model::GetObjectRequest getObjectRequest;
        ass << map["bucket"];
        getObjectRequest.SetBucket(ass.str());
        ass.str("");
        ass << map["key"];
        getObjectRequest.SetKey(ass.str());
        ass.str("");

        auto getObjectOutcome = s3Client.GetObject(getObjectRequest);
        if (!getObjectOutcome.IsSuccess()) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        std::stringstream ss;
        ss << getObjectOutcome.GetResult().GetBody().rdbuf();
        std::string data = ss.str();

        apr_bucket *b = apr_bucket_pool_create(data.c_str(), data.length(), r->pool, r->connection->bucket_alloc);
        apr_bucket_brigade *bucket_brigate = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bucket_brigate, b);
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
