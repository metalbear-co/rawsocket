use rawsocket::{self, filter::build_tcp_port_filter, RawCapture};

#[tokio::main]
async fn main() {
    let filter = build_tcp_port_filter(&[1337, 2000, 3333, 51222]);
    println!("{}", filter.to_dump());
    let capture = RawCapture::from_interface_name("lo").expect("capture creation failed");
    capture.set_filter(filter).expect("setting filter failed");
    capture.ignore_outgoing().expect("fml");
    loop {
        let packet = capture.next().await.expect("packet failed");
        println!("packet {packet:?}");
    }
}
