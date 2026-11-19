#[tokio::main]
async fn main() {
    let code = net_info::cli::run().await;
    std::process::exit(code);
}
