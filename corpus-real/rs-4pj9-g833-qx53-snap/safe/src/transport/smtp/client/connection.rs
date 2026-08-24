use std::{
    fmt::Display,
    io::{self, BufRead, BufReader, Write},
    net::{IpAddr, ToSocketAddrs},
    time::Duration,
};

#[cfg(feature = "tracing")]
use super::escape_crlf;
use super::{
    ClientCodec, MAX_RESPONSE_BYTES, MAX_RESPONSE_LINE_BYTES, NetworkStream, TlsParameters,
};
use crate::{
    address::Envelope,
    transport::smtp::{
        authentication::{Credentials, Mechanism},
        commands::{Auth, Data, Ehlo, Mail, Noop, Quit, Rcpt, Starttls},
        error,
        error::Error,
        extension::{ClientId, Extension, MailBodyParameter, MailParameter, ServerInfo},
        response::{Response, parse_response},
    },
};

macro_rules! try_smtp (
    ($err: expr, $client: ident) => ({
        match $err {
            Ok(val) => val,
            Err(err) => {
                $client.abort();
                return Err(From::from(err))
            },
        }
    })
);


pub struct SmtpConnection {


    stream: BufReader<NetworkStream>,

    panic: bool,

    server_info: ServerInfo,
}

impl SmtpConnection {

    pub fn server_info(&self) -> &ServerInfo {
        &self.server_info
    }






    pub fn connect<A: ToSocketAddrs>(
        server: A,
        timeout: Option<Duration>,
        hello_name: &ClientId,
        tls_parameters: Option<&TlsParameters>,
        local_address: Option<IpAddr>,
    ) -> Result<SmtpConnection, Error> {
        let stream = NetworkStream::connect(server, timeout, tls_parameters, local_address)?;
        let stream = BufReader::new(stream);
        let mut conn = SmtpConnection {
            stream,
            panic: false,
            server_info: ServerInfo::default(),
        };
        conn.set_timeout(timeout).map_err(error::network)?;

        let _response = conn.read_response()?;

        conn.ehlo(hello_name)?;


        #[cfg(feature = "tracing")]
        tracing::debug!("server {}", conn.server_info);
        Ok(conn)
    }

    pub fn send(&mut self, envelope: &Envelope, email: &[u8]) -> Result<Response, Error> {

        let mut mail_options = vec![];







        if envelope.has_non_ascii_addresses() {
            if !self.server_info().supports_feature(Extension::SmtpUtfEight) {

                return Err(error::client(
                    "Envelope contains non-ascii chars but server does not support SMTPUTF8",
                ));
            }
            mail_options.push(MailParameter::SmtpUtfEight);
        }


        if !email.is_ascii() {
            if !self.server_info().supports_feature(Extension::EightBitMime) {
                return Err(error::client(
                    "Message contains non-ascii chars but server does not support 8BITMIME",
                ));
            }
            mail_options.push(MailParameter::Body(MailBodyParameter::EightBitMime));
        }

        try_smtp!(
            self.command(Mail::new(envelope.from().cloned(), mail_options)),
            self
        );


        for to_address in envelope.to() {
            try_smtp!(self.command(Rcpt::new(to_address.clone(), vec![])), self);
        }


        try_smtp!(self.command(Data), self);


        let result = try_smtp!(self.message(email), self);
        Ok(result)
    }

    pub fn has_broken(&self) -> bool {
        self.panic
    }

    pub fn can_starttls(&self) -> bool {
        !self.is_encrypted() && self.server_info.supports_feature(Extension::StartTls)
    }

    #[allow(unused_variables)]
    pub fn starttls(
        &mut self,
        tls_parameters: &TlsParameters,
        hello_name: &ClientId,
    ) -> Result<(), Error> {
        if self.server_info.supports_feature(Extension::StartTls) {
            #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
            {
                try_smtp!(self.command(Starttls), self);
                self.stream.get_mut().upgrade_tls(tls_parameters)?;
                #[cfg(feature = "tracing")]
                tracing::debug!("connection encrypted");

                try_smtp!(self.ehlo(hello_name), self);
                Ok(())
            }
            #[cfg(not(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))]


            unreachable!("TLS support required but not supported");
        } else {
            Err(error::client("STARTTLS is not supported on this server"))
        }
    }


    fn ehlo(&mut self, hello_name: &ClientId) -> Result<(), Error> {
        let ehlo_response = try_smtp!(self.command(Ehlo::new(hello_name.clone())), self);
        self.server_info = try_smtp!(ServerInfo::from_response(&ehlo_response), self);
        Ok(())
    }

    pub fn quit(&mut self) -> Result<Response, Error> {
        Ok(try_smtp!(self.command(Quit), self))
    }

    pub fn abort(&mut self) {

        if !self.panic {
            self.panic = true;
            let _ = self.command(Quit);
        }
        let _ = self.stream.get_mut().shutdown(std::net::Shutdown::Both);
    }


    pub fn set_stream(&mut self, stream: NetworkStream) {
        self.stream = BufReader::new(stream);
    }


    pub fn is_encrypted(&self) -> bool {
        self.stream.get_ref().is_encrypted()
    }


    pub fn set_timeout(&mut self, duration: Option<Duration>) -> io::Result<()> {
        self.stream.get_mut().set_read_timeout(duration)?;
        self.stream.get_mut().set_write_timeout(duration)
    }


    pub fn test_connected(&mut self) -> bool {
        self.command(Noop).is_ok()
    }


    pub fn auth(
        &mut self,
        mechanisms: &[Mechanism],
        credentials: &Credentials,
    ) -> Result<Response, Error> {
        let mechanism = self
            .server_info
            .get_auth_mechanism(mechanisms)
            .ok_or_else(|| error::client("No compatible authentication mechanism was found"))?;


        let mut challenges = 10;
        let mut response = self.command(Auth::new(mechanism, credentials.clone(), None)?)?;

        while challenges > 0 && response.has_code(334) {
            challenges -= 1;
            response = try_smtp!(
                self.command(Auth::new_from_response(
                    mechanism,
                    credentials.clone(),
                    &response,
                )?),
                self
            );
        }

        if challenges == 0 {
            Err(error::response("Unexpected number of challenges"))
        } else {
            Ok(response)
        }
    }


    pub fn message(&mut self, message: &[u8]) -> Result<Response, Error> {
        self.message_iter(std::iter::once(message))
    }


    pub fn message_iter<I, B>(&mut self, message: I) -> Result<Response, Error>
    where
        I: Iterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut codec = ClientCodec::new();
        for message_part in message {
            let message_part = message_part.as_ref();
            let mut out_buf = Vec::with_capacity(message_part.len());
            codec.encode(message_part, &mut out_buf);
            self.write(out_buf.as_slice())?;
        }
        self.write(b"\r\n.\r\n")?;

        self.read_response()
    }


    pub fn command<C: Display>(&mut self, command: C) -> Result<Response, Error> {
        self.write(command.to_string().as_bytes())?;
        self.read_response()
    }


    fn write(&mut self, string: &[u8]) -> Result<(), Error> {
        self.stream
            .get_mut()
            .write_all(string)
            .map_err(error::network)?;
        self.stream.get_mut().flush().map_err(error::network)?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Wrote: {}", escape_crlf(&String::from_utf8_lossy(string)));
        Ok(())
    }


    pub fn read_response(&mut self) -> Result<Response, Error> {
        let mut buffer = String::with_capacity(100);
        let mut pre = 0;

        while self.stream.read_line(&mut buffer).map_err(error::network)? > 0 {
            if buffer.len() - pre > MAX_RESPONSE_LINE_BYTES {
                return Err(error::response("SMTP response line too long"));
            }
            if buffer.len() > MAX_RESPONSE_BYTES {
                return Err(error::response("SMTP response too large"));
            }
            pre = buffer.len();

            #[cfg(feature = "tracing")]
            tracing::debug!("<< {}", escape_crlf(&buffer));
            match parse_response(&buffer) {
                Ok((_remaining, response)) => {
                    return if response.is_positive() {
                        Ok(response)
                    } else {
                        Err(error::code(
                            response.code(),
                            Some(response.message().collect()),
                        ))
                    };
                }
                Err(nom::Err::Failure(e)) => {
                    return Err(error::response(e.to_string()));
                }
                Err(nom::Err::Incomplete(_)) => {  }
                Err(nom::Err::Error(e)) => {
                    return Err(error::response(e.to_string()));
                }
            }
        }

        Err(error::response("incomplete response"))
    }


    #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
    )]
    pub fn peer_certificate(&self) -> Result<Vec<u8>, Error> {
        self.stream.get_ref().peer_certificate()
    }












    #[cfg(feature = "boring-tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boring-tls")))]
    pub fn tls_verify_result(&self) -> Result<(), Error> {
        self.stream.get_ref().tls_verify_result()
    }


    #[cfg(any(feature = "rustls", feature = "boring-tls"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "rustls", feature = "boring-tls"))))]
    pub fn certificate_chain(&self) -> Result<Vec<Vec<u8>>, Error> {
        self.stream.get_ref().certificate_chain()
    }
}
