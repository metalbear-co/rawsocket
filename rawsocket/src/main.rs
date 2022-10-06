mod lib;

use bs_filter::idiom::ip::ip4_host;
use lib::RawCapture;

#[tokio::main]
async fn main() {
    let capture = RawCapture::from_interface_name("eth0").expect("..");
    capture
        .set_filter(
            ip4_host("8.8.8.8".parse().expect("parse fail"))
                .compile()
                .build()
                .expect("build failed"),
        )
        .expect("set filter failed");
    loop {
        let packet = capture.next().await.expect("packet");
        println!("packet: {packet:?}");
    }
}
