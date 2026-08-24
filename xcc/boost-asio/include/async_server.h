#ifndef _CC_BOOST_ASIO_
#define _CC_BOOST_ASIO_



#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <utility>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <sys/syscall.h>



#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <sstream>
#include <atomic>
#include <algorithm>
#include <list>
#include <deque>


#include <boost/asio.hpp>
#include <boost/asio/high_resolution_timer.hpp>


using boost::asio::ip::tcp;

class server
{
public:
    // we need an io_context and a port where we listen to 
    server(boost::asio::io_context& io_context, short port) 
    : m_acceptor(io_context, tcp::endpoint(tcp::v4(), port)) {
        // now we call do_accept() where we wait for clients
        do_accept();
    }
private:
    void do_accept();
private: 
    tcp::acceptor m_acceptor;
};


class session : public std::enable_shared_from_this<session>
{
public:
    // our sesseion holds the socket
    session(tcp::socket socket)  
    : m_socket(std::move(socket)) { }
    
    // and run was already called in our server, where we just wait for requests
    void run();
private:
    void wait_for_request();
private:
    tcp::socket m_socket;
    boost::asio::streambuf m_buffer;
};

#endif