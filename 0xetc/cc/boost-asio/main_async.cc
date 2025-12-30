#include "async_server.h"

int main(int argc, char* argv[])
{
    // here we create the io_context
    boost::asio::io_context io_context;
    // we'll just use an arbitrary port here 
    server s(io_context, 25000);
    // and we run until our server is alive
    io_context.run();

    return 0;
}