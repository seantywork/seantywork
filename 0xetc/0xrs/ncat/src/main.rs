mod ncat;

use std::{
    env, process::{self, ExitCode}, thread, sync::Arc
};


use ncat::ncat::{self as NCAT, NcatOptions};

fn main() -> process::ExitCode {
    

    let mut args_v = Vec::<String>::new();

    let args: Vec<String> = env::args().collect();

    let mut args_result;

    let mut rout = 0u8;

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

    for i in 1..args.len() {

        args_v.push(args[i].clone());

    };

    args_result = NCAT::parse_args(&args_v);

    match args_result {

        Ok(mut arcno) => {

            match NCAT::runner(arcno.clone()) {

                Ok(()) => {

                    return process::ExitCode::from(0u8);

                }

                Err(e) => {

                    println!("error: {}", e);

                    rout = 1u8;

                }
            }


        }

        Err(reason) => {

            println!("failed to parse args: {}", reason);

            rout = 1u8;

        }
    }

    return process::ExitCode::from(rout);
}
