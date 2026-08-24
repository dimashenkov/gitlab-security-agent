use std::{fmt::Display, net::IpAddr, time::Duration};

use futures_util::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[cfg(feature = "tokio1")]
use super::async_net::AsyncTokioStream;
#[cfg(feature = "tracing")]
use super::escape_crlf;
#[allow(deprecated)]
use super::{
    ClientCodec, MAX_RESPONSE_BYTES, MAX_RESPONSE_LINE_BYTES, TlsParameters,
    async_net::AsyncNetworkStream,
};
use crate::{
    Envelope,
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
                $client.abort().await;
                return Err(From::from(err))
            },
        }
    })
);


pub struct AsyncSmtpConnection {


    #[allow(deprecated)]
    stream: BufReader<AsyncNetworkStream>,

    panic: bool,

    server_info: ServerInfo,
}

impl AsyncSmtpConnection {

    pub fn server_info(&self) -> &ServerInfo {
        &self.server_info
    }




    #[cfg(feature = "tokio1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tokio1")))]
    pub async fn connect_with_transport(
        stream: Box<dyn AsyncTokioStream>,
        hello_name: &ClientId,
    ) -> Result<AsyncSmtpConnection, Error> {
        #[allow(deprecated)]
        let stream = AsyncNetworkStream::use_existing_tokio1(stream);
        Self::connect_impl(stream, hello_name).await
    }































    #[cfg(feature = "tokio1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tokio1")))]
    pub async fn connect_tokio1<T: tokio1_crate::net::ToSocketAddrs>(
        server: T,
        timeout: Option<Duration>,
        hello_name: &ClientId,
        tls_parameters: Option<TlsParameters>,
        local_address: Option<IpAddr>,
    ) -> Result<AsyncSmtpConnection, Error> {
        #[allow(deprecated)]
        let stream =
            AsyncNetworkStream::connect_tokio1(server, timeout, tls_parameters, local_address)
                .await?;
        Self::connect_impl(stream, hello_name).await
    }




    #[cfg(feature = "async-std1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async-std1")))]
    pub async fn connect_asyncstd1<T: async_std::net::ToSocketAddrs>(
        server: T,
        timeout: Option<Duration>,
        hello_name: &ClientId,
        tls_parameters: Option<TlsParameters>,
    ) -> Result<AsyncSmtpConnection, Error> {
        #[allow(deprecated)]
        let stream = AsyncNetworkStream::connect_asyncstd1(server, timeout, tls_parameters).await?;
        Self::connect_impl(stream, hello_name).await
    }

    #[allow(deprecated)]
    async fn connect_impl(
        stream: AsyncNetworkStream,
        hello_name: &ClientId,
    ) -> Result<AsyncSmtpConnection, Error> {
        let stream = BufReader::new(stream);
        let mut conn = AsyncSmtpConnection {
            stream,
            panic: false,
            server_info: ServerInfo::default(),
        };

        let _response = conn.read_response().await?;

        conn.ehlo(hello_name).await?;


        #[cfg(feature = "tracing")]
        tracing::debug!("server {}", conn.server_info);
        Ok(conn)
    }

    pub async fn send(&mut self, envelope: &Envelope, email: &[u8]) -> Result<Response, Error> {

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
            self.command(Mail::new(envelope.from().cloned(), mail_options))
                .await,
            self
        );


        for to_address in envelope.to() {
            try_smtp!(
                self.command(Rcpt::new(to_address.clone(), vec![])).await,
                self
            );
        }


        try_smtp!(self.command(Data).await, self);


        let result = try_smtp!(self.message(email).await, self);
        Ok(result)
    }

    pub fn has_broken(&self) -> bool {
        self.panic
    }

    pub fn can_starttls(&self) -> bool {
        !self.is_encrypted() && self.server_info.supports_feature(Extension::StartTls)
    }







    #[allow(unused_variables)]
    pub async fn starttls(
        &mut self,
        tls_parameters: TlsParameters,
        hello_name: &ClientId,
    ) -> Result<(), Error> {
        if self.server_info.supports_feature(Extension::StartTls) {
            try_smtp!(self.command(Starttls).await, self);
            self.stream.get_mut().upgrade_tls(tls_parameters).await?;
            #[cfg(feature = "tracing")]
            tracing::debug!("connection encrypted");

            try_smtp!(self.ehlo(hello_name).await, self);
            Ok(())
        } else {
            Err(error::client("STARTTLS is not supported on this server"))
        }
    }


    async fn ehlo(&mut self, hello_name: &ClientId) -> Result<(), Error> {
        let ehlo_response = try_smtp!(self.command(Ehlo::new(hello_name.clone())).await, self);
        self.server_info = try_smtp!(ServerInfo::from_response(&ehlo_response), self);
        Ok(())
    }

    pub async fn quit(&mut self) -> Result<Response, Error> {
        Ok(try_smtp!(self.command(Quit).await, self))
    }

    pub async fn abort(&mut self) {

        if !self.panic {
            self.panic = true;
            let _ = self.command(Quit).await;
        }
        let _ = self.stream.close().await;
    }


    #[allow(deprecated)]
    pub fn set_stream(&mut self, stream: AsyncNetworkStream) {
        self.stream = BufReader::new(stream);
    }


    pub fn is_encrypted(&self) -> bool {
        self.stream.get_ref().is_encrypted()
    }


    pub async fn test_connected(&mut self) -> bool {
        self.command(Noop).await.is_ok()
    }


    pub async fn auth(
        &mut self,
        mechanisms: &[Mechanism],
        credentials: &Credentials,
    ) -> Result<Response, Error> {
        let mechanism = self
            .server_info
            .get_auth_mechanism(mechanisms)
            .ok_or_else(|| error::client("No compatible authentication mechanism was found"))?;


        let mut challenges: u8 = 10;
        let mut response = self
            .command(Auth::new(mechanism, credentials.clone(), None)?)
            .await?;

        while challenges > 0 && response.has_code(334) {
            challenges -= 1;
            response = try_smtp!(
                self.command(Auth::new_from_response(
                    mechanism,
                    credentials.clone(),
                    &response,
                )?)
                .await,
                self
            );
        }

        if challenges == 0 {
            Err(error::response("Unexpected number of challenges"))
        } else {
            Ok(response)
        }
    }


    pub async fn message(&mut self, message: &[u8]) -> Result<Response, Error> {
        self.message_iter(std::iter::once(message)).await
    }


    pub async fn message_iter<I, B>(&mut self, message: I) -> Result<Response, Error>
    where
        I: Iterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut codec = ClientCodec::new();
        for message_part in message {
            let message_part = message_part.as_ref();
            let mut out_buf = Vec::with_capacity(message_part.len());
            codec.encode(message_part, &mut out_buf);
            self.write(out_buf.as_slice()).await?;
        }
        self.write(b"\r\n.\r\n").await?;

        self.read_response().await
    }


    pub async fn command<C: Display>(&mut self, command: C) -> Result<Response, Error> {
        self.write(command.to_string().as_bytes()).await?;
        self.read_response().await
    }


    async fn write(&mut self, string: &[u8]) -> Result<(), Error> {
        self.stream
            .get_mut()
            .write_all(string)
            .await
            .map_err(error::network)?;
        self.stream
            .get_mut()
            .flush()
            .await
            .map_err(error::network)?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Wrote: {}", escape_crlf(&String::from_utf8_lossy(string)));
        Ok(())
    }


    pub async fn read_response(&mut self) -> Result<Response, Error> {
        let mut buffer = String::with_capacity(100);
        let mut pre = 0;

        while self
            .stream
            .read_line(&mut buffer)
            .await
            .map_err(error::network)?
            > 0
        {
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
