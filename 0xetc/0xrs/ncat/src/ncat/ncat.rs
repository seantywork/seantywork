
use std::{
    fmt::Error,
    process,
};


pub struct NcatOptions {

    mode_client: bool,
    mode_listen: bool, 
    _client_sock_ready: bool,
    _client_sockfd: i32,
    host: String,
    port: String, 

}

impl NcatOptions {

    pub fn new() -> Self {
        Self { 
            mode_client: false, 
            mode_listen: false, 
            _client_sock_ready: false, 
            _client_sockfd: 0, 
            host: "".to_string(), 
            port: "".to_string() 
        }

    }

}

pub struct NcatComms {

    datalen: u32,
    data: Vec<u8>
}

impl NcatComms {


    pub fn new() -> Self {
        Self {

            datalen: 0,
            data: Vec::<u8>::new()
        }
    }
}


pub fn keyboard_interrupt(){

    println!("SIGINT. EXIT.");

    process::exit(0);

}


pub fn parse_args(args: &Vec<String>) -> Result<Box<NcatOptions>, String>{

    let no = NcatOptions::new();

    let retno = Box::new(no);

    return Ok(retno);
    
}

pub fn runner(ncat_opts: &mut NcatOptions) -> Result<(), String> {



    return Ok(());
}


fn client(ncat_opts: &mut NcatOptions) -> Result<(), String> {

    return Ok(());
}


fn listen_and_serve(ncat_opts: &mut NcatOptions) -> Result<(), String> {

    return Ok(());
}