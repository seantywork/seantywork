#include "ws_client.h"

int main(int argc, char *argv[])
{
	const char *greetings = "Hello World!";

	const char *host = "localhost";
	const char *path = "/wsURL";

#if defined(NO_SSL)
	const int port = 8081;
	const int secure = 0;
	mg_init_library(0);
#else
	const int port = 443;
	const int secure = 1;
	mg_init_library(MG_FEATURES_SSL);
#endif

	run_websocket_client(host, port, secure, path, greetings);
}