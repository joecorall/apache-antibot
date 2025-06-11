#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "util_script.h"
#include "apr_buckets.h"

module AP_MODULE_DECLARE_DATA antibot_module;

typedef struct {
    char *auth_backend_url;
    char *challenge_key;

    char *backend_host;
    char *backend_path;
    int backend_port;
    apr_sockaddr_t *backend_addr;
} antibot_config;

static void *create_dir_config(apr_pool_t *pool, char *dir)
{
    antibot_config *conf = apr_pcalloc(pool, sizeof(antibot_config));
    conf->auth_backend_url = apr_pstrdup(pool, "http://antibot:8888");
    conf->challenge_key = apr_pstrdup(pool, "challenge");

    char *default_url = "antibot:8888";
    char *colon = strchr(default_url, ':');
    if (colon) {
        conf->backend_host = apr_pstrndup(pool, default_url, colon - default_url);
        conf->backend_port = atoi(colon + 1);
    } else {
        conf->backend_host = apr_pstrdup(pool, default_url);
        conf->backend_port = 80;
    }
    conf->backend_path = apr_pstrdup(pool, "");
    conf->backend_addr = NULL;

    return conf;
}

static const char *set_auth_backend_url(cmd_parms *cmd, void *cfg, const char *arg)
{
    antibot_config *conf = (antibot_config*)cfg;
    conf->auth_backend_url = apr_pstrdup(cmd->pool, arg);

    // Parse URL once during configuration
    char *url_copy = apr_pstrdup(cmd->pool, arg);

    // Skip protocol if present
    if (strncmp(url_copy, "http://", 7) == 0) {
        url_copy += 7;
    }

    char *slash = strchr(url_copy, '/');
    if (slash) {
        conf->backend_path = apr_pstrdup(cmd->pool, slash + 1);
        *slash = '\0';
    } else {
        conf->backend_path = apr_pstrdup(cmd->pool, "");
    }

    char *colon = strchr(url_copy, ':');
    if (colon) {
        *colon = '\0';
        conf->backend_host = apr_pstrdup(cmd->pool, url_copy);
        conf->backend_port = atoi(colon + 1);
    } else {
        conf->backend_host = apr_pstrdup(cmd->pool, url_copy);
        conf->backend_port = 80;
    }

    // Pre-resolve the backend address
    apr_sockaddr_info_get(&conf->backend_addr, conf->backend_host, APR_INET, conf->backend_port, 0, cmd->pool);

    return NULL;
}

static const char *set_challenge_key(cmd_parms *cmd, void *cfg, const char *arg)
{
    antibot_config *conf = (antibot_config*)cfg;
    conf->challenge_key = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const command_rec antibot_cmds[] = {
    AP_INIT_TAKE1("AntibotBackendUrl", set_auth_backend_url, NULL, ACCESS_CONF, "Backend URL"),
    AP_INIT_TAKE1("AntibotChallengeKey", set_challenge_key, NULL, ACCESS_CONF, "Challenge parameter key"),
    {NULL}
};

static int make_backend_request(request_rec *r, antibot_config *conf, int is_challenge, char **out_body)
{
    apr_socket_t *sock;
    apr_status_t rv;
    apr_size_t len;
    int code = 500;

    *out_body = NULL;

    if (!conf->backend_addr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Backend address not resolved: %s", conf->backend_host);
        return 500;
    }

    rv = apr_socket_create(&sock, conf->backend_addr->family, SOCK_STREAM, APR_PROTO_TCP, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to create socket");
        return 500;
    }

    apr_socket_timeout_set(sock, apr_time_from_sec(5));
    rv = apr_socket_connect(sock, conf->backend_addr);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to connect to backend %s:%d",
                      conf->backend_host, conf->backend_port);
        apr_socket_close(sock);
        return 500;
    }

    if (is_challenge) {
        int rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
        if (rc != OK) {
            return 502;
        }

        apr_size_t total = 0;
        apr_pool_t *pool = r->pool;
        apr_size_t max_body = 65536;  // Max 64k POST body
        char *body = apr_palloc(pool, max_body);
        if (ap_should_client_block(r)) {
            char b[8192];
            long readlen;
            while ((readlen = ap_get_client_block(r, b, sizeof(b))) > 0) {
                if (total + (apr_size_t)readlen > max_body) {
                    return HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                memcpy(body + total, b, (apr_size_t)readlen);
                total += (apr_size_t)readlen;
            }
        }

        const char *req_headers = apr_psprintf(r->pool,
            "POST / HTTP/1.1\r\n"
            "Host: %s\r\n"
            "X-Forwarded-For: %s\r\n"
            "Content-Length: %lu\r\n"
            "Content-Type: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            conf->backend_host,
            r->connection->client_ip,
            (unsigned long)total,
            r->content_type ? r->content_type : "application/octet-stream"
        );

        len = strlen(req_headers);
        apr_status_t hr = apr_socket_send(sock, req_headers, &len);
        if (hr != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to send POST headers to backend");
            apr_socket_close(sock);
            return 500;
        }

        // send the client's POST body to the backend
        rv = apr_socket_send(sock, body, &total);
    } else {
        const char *req = apr_psprintf(r->pool,
            "GET / HTTP/1.1\r\n"
            "Host: %s\r\n"
            "X-Forwarded-For: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            conf->backend_host,
            r->connection->client_ip
        );

        len = strlen(req);
        rv = apr_socket_send(sock, req, &len);
    }

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to send request to backend");
        apr_socket_close(sock);
        return 500;
    }

    // Read response into buffer
    char buffer[8192];
    char *response = apr_pcalloc(r->pool, 65536);  // Max 64k response
    char *resp_ptr = response;
    apr_size_t total_len = 0;

    while (1) {
        len = sizeof(buffer);
        rv = apr_socket_recv(sock, buffer, &len);
        if (rv != APR_SUCCESS && rv != APR_EOF) {
            break;
        }
        if (len == 0) {
            break;
        }
        memcpy(resp_ptr, buffer, len);
        resp_ptr += len;
        total_len += len;
        if (rv == APR_EOF) {
            break;
        }
    }

    apr_socket_close(sock);

    // Null-terminate
    response[total_len] = '\0';

    // Parse status code from response
    if (strncmp(response, "HTTP/", 5) == 0) {
        sscanf(response, "HTTP/%*s %d", &code);
    }

    // Find start of body
    char *body_start = strstr(response, "\r\n\r\n");
    if (body_start) {
        body_start += 4; // skip past \r\n\r\n
        *out_body = apr_pstrdup(r->pool, body_start);
    } else {
        *out_body = apr_pstrdup(r->pool, "<html><body>Invalid response from backend</body></html>");
    }

    return code;
}

const char* get_query_param(const char *args, const char *key)
{
    size_t key_len = strlen(key);
    const char *p = args;

    while (p && *p) {
        if (strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
            return p + key_len + 1;
        }

        p = strchr(p, '&');
        if (p) {
            p++; // skip '&'
        }
    }

    return NULL;
}

static int antibot_handler(request_rec *r)
{
    antibot_config *conf = ap_get_module_config(r->per_dir_config, &antibot_module);
    if (!conf || !conf->backend_addr) {
        return DECLINED;
    }

    const char *client_ip = r->connection->client_ip;
    const char *args = r->args;
    char *html_content;
    int backend_response;
    int is_challenge = 0;

    // Check if this is a challenge request submission
    if (r->method_number == M_POST && args) {
        const char *val = get_query_param(r->args, conf->challenge_key);
        if (val) {
            is_challenge = 1;
        }
    }

    if (is_challenge == 0 && r->method_number != M_GET) {
        return OK;
    }

    char *response_body = NULL;
    backend_response = make_backend_request(r, conf, is_challenge, &response_body);
    switch (backend_response) {
        case HTTP_OK:
            // if this was a GET request, have apache continue processing the request
            if (is_challenge == 0 || strlen(response_body) == 0) {
                return OK;
            }
        case HTTP_FORBIDDEN:
        case HTTP_TOO_MANY_REQUESTS:
            r->content_type = "text/html";
            r->status = backend_response;
            ap_set_content_length(r, strlen(response_body));
            if (!r->header_only) {
                ap_rputs(response_body, r);
            }

            return DONE;

        default:
            r->content_type = "text/html";
            r->status = HTTP_INTERNAL_SERVER_ERROR;
            return DONE;
    }
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_access(antibot_handler, NULL, NULL, APR_HOOK_MIDDLE,
                         AP_AUTH_INTERNAL_PER_CONF);
}

module AP_MODULE_DECLARE_DATA antibot_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,          /* create per-dir config structures */
    NULL,                       /* merge per-dir config structures */
    NULL,                       /* create per-server config structures */
    NULL,                       /* merge per-server config structures */
    antibot_cmds,               /* table of config file commands */
    register_hooks              /* register hooks */
};
