#include "ws_server.h"




int main(int argc, char *argv[])
{
	/* Initialize CivetWeb library without OpenSSL/TLS support. */
	mg_init_library(0);

	/* Start the server using the advanced API. */
	struct mg_callbacks callbacks = {0};
	void *user_data = NULL;

	struct mg_init_data mg_start_init_data = {0};
	mg_start_init_data.callbacks = &callbacks;
	mg_start_init_data.user_data = user_data;
	mg_start_init_data.configuration_options = SERVER_OPTIONS;

	struct mg_error_data mg_start_error_data = {0};
	char errtxtbuf[256] = {0};
	mg_start_error_data.text = errtxtbuf;
	mg_start_error_data.text_buffer_size = sizeof(errtxtbuf);

	struct mg_context *ctx =
	    mg_start2(&mg_start_init_data, &mg_start_error_data);
	if (!ctx) {
		fprintf(stderr, "Cannot start server: %s\n", errtxtbuf);
		mg_exit_library();
		return 1;
	}

	/* Register the websocket callback functions. */
	mg_set_websocket_handler_with_subprotocols(ctx,
	                                           WS_URL,
	                                           &wsprot,
	                                           ws_connect_handler,
	                                           ws_ready_handler,
	                                           ws_data_handler,
	                                           ws_close_handler,
	                                           user_data);

	/* Let the server run. */
	printf("Websocket server running\n");
	while (!g_exit) {
		sleep(1);
	}
	printf("Websocket server stopping\n");

	/* Stop server, disconnect all clients. Then deinitialize CivetWeb library.
	 */
	mg_stop(ctx);
	mg_exit_library();
}