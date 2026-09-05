#include "http_server.h"


int exitNow = 0;
unsigned request = 0;


int SendJSON(struct mg_connection *conn, cJSON *json_obj)
{
	char *json_str = cJSON_PrintUnformatted(json_obj);
	size_t json_str_len = strlen(json_str);

	/* Send HTTP message header (+1 for \n) */
	mg_send_http_ok(conn, "application/json; charset=utf-8", json_str_len + 1);

	/* Send HTTP message content */
	mg_write(conn, json_str, json_str_len);

	/* Add a newline. This is not required, but the result is more
	 * human-readable in a debugger. */
	mg_write(conn, "\n", 1);

	/* Free string allocated by cJSON_Print* */
	cJSON_free(json_str);

	return (int)json_str_len;
}


int RestGET(struct mg_connection *conn, const char *p1, const char *p2)
{
	cJSON *obj = cJSON_CreateObject();

	if (!obj) {
		/* insufficient memory? */
		mg_send_http_error(conn, 500, "Server error");
		return 500;
	}

	printf("GET %s/%s\n", p1, p2);
	cJSON_AddStringToObject(obj, "version", CIVETWEB_VERSION);
	cJSON_AddStringToObject(obj, "path1", p1);
	cJSON_AddStringToObject(obj, "path2", p2);
	cJSON_AddNumberToObject(obj, "request", ++request);
	SendJSON(conn, obj);
	cJSON_Delete(obj);

	return 200;
}



int RestHandler(struct mg_connection *conn, void *cbdata)
{

    printf("1\n");
	char path1[1024], path2[1024];
	const struct mg_request_info *ri = mg_get_request_info(conn);
	const char *url = ri->local_uri;
	size_t url_len = strlen(url);

    printf("2\n");

	/* Pattern matching */
#if 0 /* Old version: User code had to split the url. */
	if (2
	    != mg_split(
	           url, EXAMPLE_URI, path1, sizeof(path1), path2, sizeof(path2))) {
		mg_send_http_error(conn, 404, "Invalid path: %s\n", url);
		return 404;
	}
#else /* New version: User mg_match. */
	struct mg_match_context mcx;
	mcx.case_sensitive = 0;

	ptrdiff_t ret = mg_match(EXAMPLE_URI, url, &mcx);
	if ((ret != url_len) || (mcx.num_matches != 2)) {
		/* Note: Could have done this with a $ at the end of the match
		 * pattern as well. Then we would have to check for a return value
		 * of -1 only. Here we use this version as minimum modification
		 * of the existing code. */
		printf("Match ret: %i\n", (int)ret);
		mg_send_http_error(conn, 404, "Invalid path: %s\n", url);
		return 404;
	}
	memcpy(path1, mcx.match[0].str, mcx.match[0].len);
	path1[mcx.match[0].len] = 0;
	memcpy(path2, mcx.match[1].str, mcx.match[1].len);
	path2[mcx.match[1].len] = 0;
#endif


	(void)cbdata; /* currently unused */

	/* According to method */
	if (0 == strcmp(ri->request_method, "GET")) {
		return RestGET(conn, path1, path2);
	}

	/* this is not a GET request */
	mg_send_http_error(
	    conn, 405, "Only GET method supported");
	return 405;
}

int ExitHandler(struct mg_connection *conn, void *cbdata)
{
	mg_printf(conn,
	          "HTTP/1.1 200 OK\r\nContent-Type: "
	          "text/plain\r\nConnection: close\r\n\r\n");
	mg_printf(conn, "Server will shut down.\n");
	mg_printf(conn, "Bye!\n");
	exitNow = 1;
	return 1;
}


int log_message(const struct mg_connection *conn, const char *message)
{
	puts(message);
	return 1;
}
