
use std::{
    fs, io::{self, BufRead, Read, Write}, net::{TcpListener, TcpStream}, process, sync::{mpsc::{self, Receiver, Sender}, Arc}, thread, time::Duration
};

use byteorder::{LittleEndian, BigEndian, ByteOrder, ReadBytesExt};


#[derive(Clone)]
pub struct NcatOptions {

    pub mode_client: bool,
    pub mode_listen: bool, 
    pub host: String,
    pub port: String, 
    pub serve_content: String

}

impl NcatOptions {

    pub fn new() -> Self {

        Self { 
            mode_client: false, 
            mode_listen: false, 
            host: "".to_string(), 
            port: "".to_string(),
            serve_content: "".to_string()
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

pub async fn runner(mut ncat_opts: NcatOptions) -> Result<(), String> {

    let (tx, rx) = mpsc::channel::<NcatOptions>();

    let (txStream, rxStream) = mpsc::channel::<TcpStream>();


    if ncat_opts.mode_client {

        tokio::spawn(get_thread(ncat_opts.clone(), tx, rxStream));

        let result = client(ncat_opts.clone(), txStream);

        return result;

    }


    if ncat_opts.mode_listen {

        tokio::spawn(get_thread(ncat_opts.clone(), tx, rxStream));

        let mut ncat_opts_updated: NcatOptions = NcatOptions::new();

        let timeout = Duration::new(0, 500000000);

        match rx.recv_timeout(timeout) {

            Ok(received) => {

                ncat_opts_updated = received;

            }

            Err(e) => {

                ncat_opts_updated = ncat_opts.clone();
            }
        };


        let result = listen_and_serve(ncat_opts_updated.clone());
        
        return result;

    }

    return Err("unsupported mode".to_string());

}


fn client(mut ncat_opts: NcatOptions, tx: Sender<TcpStream>) -> Result<(), String> {

    let mut stream = TcpStream::connect((ncat_opts.host.as_str(), ncat_opts.port.to_string().parse::<u16>().unwrap())).unwrap();

    let mut io_stream = stream.try_clone().unwrap();

    let mut io_stream_reader = io_stream.try_clone().unwrap();

    match tx.send(io_stream_reader) {

        Ok(())=> {

        }

        Err(e) => {

            println!("terrible channel send error: {}", e);


        }

    };

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        
        let message = line.unwrap();
        
        if message == "exit".to_string() {

            break;

        }

        let mut header = [0u8; 4];

        let mut message_size = [0u32];

        message_size[0] = message.len() as u32;

        BigEndian::write_u32_into(&message_size, &mut header);

        let mut wbuff_vec = header.to_vec();

        let mut message_vec = message.as_bytes().to_vec();

        wbuff_vec.append(&mut message_vec);

        //let wbuff = wbuff_vec.as_slice();

        let wsize = io_stream.write(&wbuff_vec).unwrap();

        if wsize <= 0 {

            println!("failed to write: {}", wsize);
        }
    }

    return Ok(());
}


fn listen_and_serve(mut ncat_opts: NcatOptions) -> Result<(), String> {

    let mut listenaddr = ncat_opts.host.clone();

    listenaddr += &":";

    listenaddr += ncat_opts.port.as_str();

    let listener = TcpListener::bind(listenaddr).unwrap();

    for stream in listener.incoming() {

        match stream {

            Ok(mut io_stream) =>{

                let mut header = [0u8; 4];

                loop {
            
                    let mut valread = 0;
            
            
                    loop {
            
                        let mut n = io_stream.read(&mut header[valread..]).unwrap();
            
                        if n == 0 {
            
                            println!("read header error");
            
                            break;
                        }
            
                        valread += n;
            
                        if valread == 4 {
            
                            break;
                        }
                    }
            
            
                    let mut datalen = LittleEndian::read_u32(&mut header);
                    
                    println!("datalen: {}", datalen);

                    let mut data = Vec::<u8>::with_capacity(datalen as usize);
            
                    valread = 0;
            
                    loop {
            
                        let mut n = io_stream.read(&mut data[valread..]).unwrap();
            
                        if n == 0 {
            
                            println!("read data error");
            
                            break;
                        }
            
                        valread += n;
            
                        if valread == datalen as usize {
            
                            break;
                        }
            
                    }
            
                    println!("{}", String::from_utf8(data).unwrap());
                }
            

            }
            Err(e) => {
                println!("accept error: {}", e);
            }

        }

    }

    return Ok(());
}


async fn get_thread(mut ncat_opts: NcatOptions, tx: Sender<NcatOptions>, rx: Receiver<TcpStream>) {

    if(ncat_opts.mode_client) {

        let mut io_stream = rx.recv().unwrap();

        let mut header = [0u8; 4];

        loop {

            let mut valread = 0;


            loop {

                let mut n = io_stream.read(&mut header[valread..]).unwrap();

                if n == 0 {
    
                    println!("read header error");
    
                    break;
                }

                valread += n;

                if valread == 4 {

                    break;
                }
            }


            let mut datalen = BigEndian::read_u32(&mut header);

            let mut data = Vec::<u8>::with_capacity(datalen as usize);

            valread = 0;

            loop {

                let mut n = io_stream.read(&mut data[valread..]).unwrap();

                if n == 0 {
    
                    println!("read data error");
    
                    break;
                }

                valread += n;

                if valread == datalen as usize {

                    break;
                }

            }

            println!("{}", String::from_utf8(data).unwrap());

        }

    } else if (ncat_opts.mode_listen) {





    }


}