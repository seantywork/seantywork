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
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/write.hpp>
#include <cstdio>

using boost::asio::ip::tcp;
using boost::asio::awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::use_awaitable;
namespace this_coro = boost::asio::this_coro;


awaitable<void> echo(tcp::socket socket);


awaitable<void> listener();


#endif