use libraspserver::comm::Server;
use libraspserver::listen_stdin;
use tokio;
use std::thread;
use std::process::exit;

async fn start_rasp_server(path: &'static str) -> Result<(), String> {
    let mut server = Server::new(path);
    server.start_bind().await
}

#[tokio::main]
async fn main() {
    env_logger::init();
    thread::spawn(||{
	listen_stdin();
	exit(1);
    });
    let _ = match start_rasp_server("/var/run/smith_agent.sock").await {
        Err(e) => {
            println!("err: {}", e);
            return
        }
        Ok(_) => {},
    };
    println!("exit normaly");
}
