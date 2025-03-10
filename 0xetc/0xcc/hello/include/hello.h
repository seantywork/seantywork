#ifndef _HELLO_
#define _HELLO_


#include <string>
#include <iostream>
#include <fstream>
#include <vector>



class hello{
public:
 
    hello(std::string phrase){
        _myheart = phrase;
    };

    

private: 
    std::string _myheart;

};


#endif 