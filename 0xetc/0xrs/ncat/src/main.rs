mod ncat;

use std::{
    env, ops::Deref, process::{self, ExitCode}, thread, sync::Arc
};

use tokio;

use ncat::ncat::{self as NCAT, NcatOptions};

fn main() -> process::ExitCode {
    
    let args: Vec<String> = env::args().collect();

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

        Ok(mut arcno) => {

            let mut ncat_opts = arcno.as_ref().clone();

            match NCAT::runner(ncat_opts.clone()) {

                Ok(()) => {

                    return process::ExitCode::from(0u8);

                }

                Err(e) => {

                    println!("error: {}", e);
                }
            }


        }

        Err(reason) => {

            println!("failed to parse args: {}", reason);
        }
    }

    return process::ExitCode::from(0u8);
}
