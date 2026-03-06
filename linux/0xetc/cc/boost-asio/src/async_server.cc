#include "async_server.h"

void server::do_accept() {
    // this is an async accept which means the lambda function is 
    // executed, when a client connects
    m_acceptor.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
            // let's see where we created our session
            std::cout << "creating session on: " 
                << socket.remote_endpoint().address().to_string() 
                << ":" << socket.remote_endpoint().port() << '\n';
            // create a session where we immediately call the run function
            // note: the socket is passed to the lambda here
            std::make_shared<session>(std::move(socket))->run();
        } else {
            std::cout << "error: " << ec.message() << std::endl;
        }
        // since we want multiple clients to connnect, wait for the next one by calling do_accept()
        do_accept();
    });
}


void session::run() {
    wait_for_request();
}

void session::wait_for_request() {
        // since we capture `this` in the callback, we need to call shared_from_this()
    auto self(shared_from_this());
    // and now call the lambda once data arrives
    // we read a string until the null termination character
    boost::asio::async_read_until(m_socket, m_buffer, "\0", 
    [this, self](boost::system::error_code ec, std::size_t /*length*/)
    {
        // if there was no error, everything went well and for this demo
        // we print the data to stdout and wait for the next request
        if (!ec)  {
            std::string data{
                std::istreambuf_iterator<char>(&m_buffer), 
                std::istreambuf_iterator<char>() 
            };
            // we just print the data, you can here call other api's 
            // or whatever the server needs to do with the received data

            int n = data.size();

            boost::asio::async_write(m_socket, boost::asio::buffer(data, n),
                [this, self](std::error_code ec, std::size_t /*length*/){

                    if(!ec){

                        wait_for_request();
                    } else {

                        std::cout << "write error: " << ec << std::endl;
                    }

                });

        } else {
            std::cout << "error: " << ec << std::endl;;
        }
    });
}