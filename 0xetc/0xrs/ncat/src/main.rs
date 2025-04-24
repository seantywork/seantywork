mod ncat;

use std::{
    env, 
    fs, 
    net::{TcpListener, TcpStream}, 
    process::{self, ExitCode}, 
    thread
};

use ncat::ncat::{self as NCAT, NcatOptions};


fn main() -> process::ExitCode {
    
    let args: Vec<String> = env::args().collect();

    let ncat_opts: &mut NCAT::NcatOptions;

    if args.len() < 2 {

        println!("too few arguments");

        return process::ExitCode::from(1u8);
    }


    match ctrlc::set_handler(move || {
        NCAT::keyboard_interrupt();
    }) {

        Ok(()) => {


        }

        Err(error) => {

            println!("failed to add signal handler: {}", error.to_string());

        }

    }

    let mut args_v = Vec::<String>::new();

    for i in 1..args.len() {

        args_v.push(args[i].clone());

    };

    let mut args_result = NCAT::parse_args(&args_v);

    match args_result {

        Ok(mut boxno) => {

            ncat_opts = boxno.as_mut();

        }

        Err(reason) => {

            println!("failed to parse args: {}", reason);
        }
    }




    return process::ExitCode::from(0u8);
}
