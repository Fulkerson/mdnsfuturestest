extern crate dns_parser;
extern crate futures;
extern crate net2;
extern crate tokio_core;

use std::io;
use std::net::Ipv4Addr;
use std::net::{SocketAddr, SocketAddrV4};

use net2::unix::UnixUdpBuilderExt;
use futures::{Sink, Stream};
use tokio_core::net::{UdpCodec, UdpSocket};
use tokio_core::reactor::Core;

pub struct MdnsCodec;

impl UdpCodec for MdnsCodec {
    type In = dns_parser::Packet;
    type Out = (SocketAddr, dns_parser::Builder);

    fn decode(&mut self, addr: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        Ok(dns_parser::Packet::parse(buf).unwrap())
    }

    fn encode(&mut self, (addr, builder): Self::Out, into: &mut Vec<u8>) -> SocketAddr {
        let packet_data = builder.build().unwrap();
        into.extend(&packet_data);
        addr
    }
}

fn main() {
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let multicast_addr = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
    let inaddr_any = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 5353);
    let ipv4 = Ipv4Addr::new(0, 0, 0, 0);

    let socket = net2::UdpBuilder::new_v4()
        .unwrap()
        .reuse_address(true)
        .unwrap()
        .reuse_port(true)
        .unwrap()
        .bind(inaddr_any)
        .unwrap();

    let socket = UdpSocket::from_socket(socket, &handle).unwrap();

    socket
        .join_multicast_v4(&multicast_addr.ip(), &inaddr_any.ip())
        .unwrap();

    let (sink, stream) = socket.framed(MdnsCodec).split();

    let mut builder = dns_parser::Builder::new_query(0, false);
    builder.add_question(
        "_raop._tcp.local",
        dns_parser::QueryType::PTR,
        dns_parser::QueryClass::IN,
    );

    let s = sink.send((std::net::SocketAddr::V4(multicast_addr), builder));

    core.run(s);
}
