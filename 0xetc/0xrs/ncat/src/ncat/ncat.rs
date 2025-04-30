
use std::{
    fs, io::{self, BufRead, Read, Write}, mem, net::{TcpListener, TcpStream}, ops::Deref, process, sync::{mpsc::{self, Receiver, SyncSender}, Arc, Mutex}, thread, time::Duration
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


pub fn parse_args(args: &Vec<String>) -> Result<Arc<Mutex<NcatOptions>>, String>{

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


    let retno = Arc::new(Mutex::new(no));

    return Ok(retno);
    
}

pub fn runner(mut ncat_opts: Arc<Mutex<NcatOptions>>) -> Result<(), String> {

    let (txString, rxString) = mpsc::sync_channel::<String>(1);

    let (txStream, rxStream) = mpsc::sync_channel::<TcpStream>(1);

    let mut nolock = ncat_opts.lock().unwrap();

    let mut nopts = ncat_opts.clone();

    if nolock.mode_client {

        mem::drop(nolock);

        thread::spawn(move || get_thread(nopts.clone(), Arc::new(Mutex::new(rxStream)), Arc::new(txString)));

        let result = client(ncat_opts.clone(), Arc::new(txStream));

        return result;

    }


    if nolock.mode_listen {

        mem::drop(nolock);

        thread::spawn(move || get_thread(nopts.clone(), Arc::new(Mutex::new(rxStream)), Arc::new(txString)));

        let timeout = Duration::new(0, 50000000);

        let done = rxString.recv_timeout(timeout).unwrap();

        if done.as_str() == "done" {

            //let mut tmp = ncat_opts.lock().unwrap().serve_content.clone();

            //println!("done: {}", tmp);
        }


        let result = listen_and_serve(ncat_opts.clone());

        return result;

    }

    return Err("unsupported mode".to_string());

}


fn client(mut ncat_opts: Arc<Mutex<NcatOptions>>, tx: Arc<SyncSender<TcpStream>>) -> Result<(), String> {

    let mut nolock = ncat_opts.lock().unwrap();

    let mut stream = TcpStream::connect((nolock.host.as_str(), nolock.port.to_string().parse::<u16>().unwrap())).unwrap();

    let mut io_stream = stream.try_clone().unwrap();

    let mut io_stream_reader = io_stream.try_clone().unwrap();

    match tx.send(io_stream_reader) {

        Ok(())=> {

        }

        Err(e) => {

            println!("terrible channel send error: {}", e);


        }

    };

    mem::drop(nolock);

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        
        let message = line.unwrap();
        
        if message.trim() == "exit" {

            break;

        }

        let mut header = [0u8; 4];

        let mut message_size = [0u32];

        message_size[0] = message.len() as u32;

        BigEndian::write_u32_into(&message_size, &mut header);

        let mut wbuff_vec = header.to_vec();

        let mut message_vec = message.as_bytes().to_vec();

        wbuff_vec.append(&mut message_vec);

        let wsize = io_stream.write(&wbuff_vec).unwrap();

        if wsize <= 0 {

            println!("failed to write: {}", wsize);
        }

    }

    return Ok(());
}


fn listen_and_serve(mut ncat_opts: Arc<Mutex<NcatOptions>>) -> Result<(), String> {

    let mut nolock = ncat_opts.lock().unwrap();

    let mut listenaddr = nolock.host.clone();

    let mut serve_content = nolock.serve_content.clone();

    listenaddr += &":";

    listenaddr += nolock.port.as_str();

    let listener = TcpListener::bind(listenaddr).unwrap();

    mem::drop(nolock);

    for stream in listener.incoming() {

        match stream {

            Ok(mut io_stream) =>{

                if serve_content != "" {

                    let mut header = [0u8; 4];

                    let mut message_size = [0u32];

                    message_size[0] = serve_content.len() as u32;

                    BigEndian::write_u32_into(&message_size, &mut header);

                    let mut wbuff_vec = header.to_vec();

                    let mut message_vec = serve_content.as_bytes().to_vec();

                    wbuff_vec.append(&mut message_vec);

                    let wsize = io_stream.write(&wbuff_vec).unwrap();

                    if wsize <= 0 {

                        println!("failed to write serve content: {}", wsize);
                    }


                }

                let mut header = [0u8; 4];

                loop {
            
                    let mut valread = 0;
            
                    let mut sout = 0;
            
                    loop {
            
                        let mut n = io_stream.read(&mut header[valread..]).unwrap();
            
                        if n == 0 {
            
                            println!("read header error");
                            
                            sout = -1;

                            break;
                        }
            
                        valread += n;
            
                        if valread == 4 {
            
                            break;
                        }
                    }

                    if sout < 0 {

                        break;
                    }
            
                    let mut datalen = BigEndian::read_u32(&mut header);

                    let mut data = vec![0; datalen as usize];
        
                    valread = 0;
            
                    loop {
            
                        let mut n = io_stream.read(&mut data[valread..]).unwrap();
            
                        if n == 0 {
            
                            println!("read data error");
            
                            sout = -1;

                            break;
                        }
            
                        valread += n;
            
                        if valread == datalen as usize {
            
                            break;
                        }
            
                    }
            
                    if sout < 0 {

                        break;
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


fn get_thread(mut ncat_opts: Arc<Mutex<NcatOptions>>, rx: Arc<Mutex<Receiver<TcpStream>>>, tx: Arc<SyncSender<String>>) {

    let mut nolock = ncat_opts.lock().unwrap();

    if(nolock.mode_client) {

        mem::drop(nolock);

        let mut io_stream = rx.lock().unwrap().recv().unwrap();

        let mut header = [0u8; 4];

        loop {

            let mut valread = 0;

            let mut sout = 0;

            loop {

                let mut n = io_stream.read(&mut header[valread..]).unwrap();

                if n == 0 {
    
                    println!("read header error");
                    
                    sout = -1;

                    break;
                }

                valread += n;

                if valread == 4 {

                    break;
                }
            }

            if sout < 0 {

                break;
            }


            let mut datalen = BigEndian::read_u32(&mut header);

            let mut data = vec![0; datalen as usize];

            valread = 0;

            loop {

                let mut n = io_stream.read(&mut data[valread..]).unwrap();

                if n == 0 {
    
                    println!("read data error");
    
                    sout = -1;

                    break;
                }

                valread += n;

                if valread == datalen as usize {

                    break;
                }

            }

            if sout < 0 {

                break;
            }

            println!("{}", String::from_utf8(data).unwrap());

        }

    } else if (nolock.mode_listen) {

        let mut retstr = String::new();

        let stdin = io::stdin();
        for line in stdin.lock().lines() {

            match line {

                Ok(s) =>{

                    retstr += s.as_str();

                }
    
                Err(e) => {
                    
                    break;
    
                }
            }


        }

        println!("loaded: {}", retstr);

        nolock.serve_content = retstr.clone();

        tx.send("done".to_string());

    }


}