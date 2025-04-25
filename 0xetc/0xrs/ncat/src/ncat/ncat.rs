
use std::{
    fmt::Error, ops::Deref, process, sync::Arc
};

use pipe::{PipeReader, PipeWriter};


#[derive(Clone)]
pub struct NcatOptions {

    pub _server_sig_tx: PipeWriter,
    pub _server_sig_rx: PipeReader,
    pub mode_client: bool,
    pub mode_listen: bool, 
    pub _client_sock_ready: bool,
    pub _client_sockfd: i32,
    pub host: String,
    pub port: String, 

}

impl NcatOptions {

    pub fn new() -> Self {

        let (mut read, mut write) = pipe::pipe();

        Self { 
            mode_client: false, 
            mode_listen: false, 
            _client_sock_ready: false, 
            _client_sockfd: 0, 
            _server_sig_rx: read,
            _server_sig_tx: write,
            host: "".to_string(), 
            port: "".to_string() 
        }

    }



}

pub struct NcatComms {

    pub datalen: u32,
    pub data: Vec<u8>
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


pub fn parse_args(args: &Vec<String>) -> Result<Arc<NcatOptions>, String>{

    let mut no = NcatOptions::new();

    let arglen = args.len();

    if arglen < 2 {


        return Err("needs argument: [-l|--listen] host port".to_string());

    }

    let arglen_nohp = arglen - 2;


    for i in 0..arglen_nohp {

        if (args[i] == "--listen".to_string()) ||
            (args[i] == "-l".to_string()) {

            no.mode_listen = true;

        }

    }

    if !no.mode_listen {
        no.mode_client = true;
    }

    no.host = args[arglen_nohp].clone();
    no.port = args[arglen_nohp + 1].clone();


    let retno = Arc::new(no);

    return Ok(retno);
    
}

pub fn runner(ncat_opts: &mut NcatOptions) -> Result<(), String> {

    let mut status = 0;

    if ncat_opts.mode_listen {



    }


    return Ok(());
}


fn client(ncat_opts: &mut NcatOptions) -> Result<(), String> {

    return Ok(());
}


fn listen_and_serve(ncat_opts: &mut NcatOptions) -> Result<(), String> {

    return Ok(());
}