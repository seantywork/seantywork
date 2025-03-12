#include "hello.h"


hello::hello(std::string message):_message(message){
    std::cout << "on: " << _get_message() << std::endl;
}

hello::~hello(){
    std::cout<< "gone: " << _message << std::endl;
}

void hello::operator=(std::shared_ptr<hello> obj){

    _message = obj->_message;

}


bool hello::operator==(std::shared_ptr<hello> obj){

    if(_message == obj->_message){

        return true;

    } else {

        return false;
    }

}

void hello::speak(){

    std::cout << _message << std::endl;

}

void hello::_set_message(std::string m){

    _message = m;
}


std::string hello::_get_message(){

    return _message;
}

hello_ex::hello_ex(std::string message): hello(message){}

void hello_ex::set_message(std::string m){

    _set_message(m);
}

std::string hello_ex::get_message(){


    return _get_message();

}



int main(){

    std::shared_ptr<hello> h1 = std::make_shared<hello>("im one");

    std::shared_ptr<hello> h2 = std::make_shared<hello>("im two");
    
    if(h1 == h2){

        std::cout << "same" << std::endl;

    } else {

        std::cout << "different" << std::endl;

    }


    h1 = h2;


    h1->speak();

    h2->speak();

    if(h1 == h2){

        std::cout << "same" << std::endl;

    } else {

        std::cout << "different" << std::endl;

    } 


    hello h3("im three");
    hello h4("im four");

    h3 = std::move(h4);

    h3.speak();

    h4.speak();

    hello_ex *hex = new hello_ex("im ex");

    std::string m = hex->get_message();

    std::cout << m << std::endl;

    hex->set_message("im ex2");

    m = hex->get_message();

    std::cout << m << std::endl;

    delete hex;


    return 0;
}