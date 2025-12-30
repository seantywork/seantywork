#ifndef _CC_HELLO_
#define _CC_HELLO_




#include <cstdio>
#include <string>
#include <memory>
#include <iostream>
#include <fstream>
#include <vector>


class hello{


public:

    hello(std::string message);

    ~hello();

    void operator=(std::shared_ptr<hello> obj);

    bool operator==(std::shared_ptr<hello> obj);

    void speak();

protected:

    void _set_message(std::string m);
    std::string _get_message();

private:

    std::string _message;

};

class hello_ex: hello {

public:

    hello_ex(std::string message);

    void set_message(std::string m);

    std::string get_message();

};


#endif