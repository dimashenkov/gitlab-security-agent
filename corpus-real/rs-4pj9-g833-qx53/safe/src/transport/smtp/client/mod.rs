























#[cfg(feature = "serde")]
use std::fmt::Debug;

#[cfg(any(feature = "tokio1", feature = "async-std1"))]
pub use self::async_connection::AsyncSmtpConnection;
#[cfg(any(feature = "tokio1", feature = "async-std1"))]
#[allow(deprecated)]
pub use self::async_net::AsyncNetworkStream;
#[cfg(feature = "tokio1")]
pub use self::async_net::AsyncTokioStream;
use self::net::NetworkStream;
#[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
pub(super) use self::tls::InnerTlsParameters;
#[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
pub use self::tls::TlsVersion;
pub use self::{
    connection::SmtpConnection,
    tls::{Certificate, CertificateStore, Identity, Tls, TlsParameters, TlsParametersBuilder},
};

#[cfg(any(feature = "tokio1", feature = "async-std1"))]
mod async_connection;
#[cfg(any(feature = "tokio1", feature = "async-std1"))]
mod async_net;
mod connection;
mod net;
mod tls;


pub(super) const MAX_RESPONSE_BYTES: usize = 100_000;


pub(super) const MAX_RESPONSE_LINE_BYTES: usize = 1000;


#[derive(Debug)]
struct ClientCodec {
    status: CodecStatus,
}

impl ClientCodec {

    pub(crate) fn new() -> Self {
        Self {
            status: CodecStatus::StartOfNewLine,
        }
    }


    fn encode(&mut self, frame: &[u8], buf: &mut Vec<u8>) {
        for &b in frame {
            buf.push(b);
            match (b, self.status) {
                (b'\r', _) => {
                    self.status = CodecStatus::StartingNewLine;
                }
                (b'\n', CodecStatus::StartingNewLine) => {
                    self.status = CodecStatus::StartOfNewLine;
                }
                (_, CodecStatus::StartingNewLine) => {
                    self.status = CodecStatus::MiddleOfLine;
                }
                (b'.', CodecStatus::StartOfNewLine) => {
                    self.status = CodecStatus::MiddleOfLine;
                    buf.push(b'.');
                }
                (_, CodecStatus::StartOfNewLine) => {
                    self.status = CodecStatus::MiddleOfLine;
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(clippy::enum_variant_names)]
enum CodecStatus {

    MiddleOfLine,

    StartingNewLine,

    StartOfNewLine,
}



#[cfg(feature = "tracing")]
pub(super) fn escape_crlf(string: &str) -> String {
    string.replace("\r\n", "<CRLF>")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_codec() {
        let mut buf = Vec::new();
        let mut codec = ClientCodec::new();

        codec.encode(b".\r\n", &mut buf);
        codec.encode(b"test\r\n", &mut buf);
        codec.encode(b"test\r\n\r\n", &mut buf);
        codec.encode(b".\r\n", &mut buf);
        codec.encode(b"\r\ntest", &mut buf);
        codec.encode(b"te\r\n.\r\nst", &mut buf);
        codec.encode(b"test", &mut buf);
        codec.encode(b"test.", &mut buf);
        codec.encode(b"test\n", &mut buf);
        codec.encode(b".test\n", &mut buf);
        codec.encode(b"test", &mut buf);
        codec.encode(b"test", &mut buf);
        codec.encode(b"test\r\n", &mut buf);
        codec.encode(b".test\r\n", &mut buf);
        codec.encode(b"test.\r\n", &mut buf);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "..\r\ntest\r\ntest\r\n\r\n..\r\n\r\ntestte\r\n..\r\nsttesttest.test\n.test\ntesttesttest\r\n..test\r\ntest.\r\n"
        );
    }

    #[test]
    #[cfg(feature = "tracing")]
    fn test_escape_crlf() {
        assert_eq!(escape_crlf("\r\n"), "<CRLF>");
        assert_eq!(escape_crlf("EHLO my_name\r\n"), "EHLO my_name<CRLF>");
        assert_eq!(
            escape_crlf("EHLO my_name\r\nSIZE 42\r\n"),
            "EHLO my_name<CRLF>SIZE 42<CRLF>"
        );
    }
}
