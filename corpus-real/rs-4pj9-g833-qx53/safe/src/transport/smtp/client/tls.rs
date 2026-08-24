use std::fmt::{self, Debug};
#[cfg(feature = "rustls")]
use std::sync::Arc;

#[cfg(feature = "boring-tls")]
use boring::{
    pkey::PKey,
    ssl::{SslConnector, SslVersion},
    x509::store::X509StoreBuilder,
};
#[cfg(feature = "native-tls")]
use native_tls::{Protocol, TlsConnector};
#[cfg(feature = "rustls")]
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{self, CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    server::ParsedCertificate,
};

#[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
use crate::transport::smtp::{Error, error};


#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
#[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
pub enum TlsVersion {







    Tlsv10,







    Tlsv11,





    Tlsv12,






    Tlsv13,
}






#[derive(Clone)]
#[allow(missing_copy_implementations)]
#[cfg_attr(
    not(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")),
    deprecated(
        note = "starting from lettre v0.12 `Tls` won't be available when none of the TLS backends are enabled"
    )
)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
)]
pub enum Tls {









    None,









    #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
    )]
    Opportunistic(TlsParameters),









    #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
    )]
    Required(TlsParameters),







    #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
    )]
    Wrapper(TlsParameters),
}

impl Debug for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::None => f.pad("None"),
            #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
            Self::Opportunistic(_) => f.pad("Opportunistic"),
            #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
            Self::Required(_) => f.pad("Required"),
            #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
            Self::Wrapper(_) => f.pad("Wrapper"),
        }
    }
}


#[allow(missing_copy_implementations)]
#[derive(Clone, Debug, Default)]
#[cfg_attr(
    not(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")),
    deprecated(
        note = "starting from lettre v0.12 `CertificateStore` won't be available when none of the TLS backends are enabled"
    )
)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
)]
pub enum CertificateStore {










    #[default]
    Default,



    #[cfg(all(feature = "rustls", feature = "webpki-roots"))]
    WebpkiRoots,

    None,
}


#[derive(Clone)]
#[cfg_attr(
    not(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")),
    deprecated(
        note = "starting from lettre v0.12 `TlsParameters` won't be available when none of the TLS backends are enabled"
    )
)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
)]
pub struct TlsParameters {
    pub(crate) connector: InnerTlsParameters,

    pub(super) domain: String,
}


#[derive(Debug, Clone)]
#[cfg_attr(
    not(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")),
    deprecated(
        note = "starting from lettre v0.12 `TlsParametersBuilder` won't be available when none of the TLS backends are enabled"
    )
)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
)]
pub struct TlsParametersBuilder {
    domain: String,
    cert_store: CertificateStore,
    root_certs: Vec<Certificate>,
    identity: Option<Identity>,
    accept_invalid_hostnames: bool,
    accept_invalid_certs: bool,
    #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
    min_tls_version: TlsVersion,
}

impl TlsParametersBuilder {

    pub fn new(domain: String) -> Self {
        Self {
            domain,
            cert_store: CertificateStore::Default,
            root_certs: Vec::new(),
            identity: None,
            accept_invalid_hostnames: false,
            accept_invalid_certs: false,
            #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
            min_tls_version: TlsVersion::Tlsv12,
        }
    }


    pub fn certificate_store(mut self, cert_store: CertificateStore) -> Self {
        self.cert_store = cert_store;
        self
    }




    pub fn add_root_certificate(mut self, cert: Certificate) -> Self {
        self.root_certs.push(cert);
        self
    }




    pub fn identify_with(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }














    #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
    )]
    pub fn dangerous_accept_invalid_hostnames(mut self, accept_invalid_hostnames: bool) -> Self {
        self.accept_invalid_hostnames = accept_invalid_hostnames;
        self
    }




    #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
    )]
    pub fn set_min_tls_version(mut self, min_tls_version: TlsVersion) -> Self {
        self.min_tls_version = min_tls_version;
        self
    }

















    pub fn dangerous_accept_invalid_certs(mut self, accept_invalid_certs: bool) -> Self {
        self.accept_invalid_certs = accept_invalid_certs;
        self
    }



    #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
    )]
    pub fn build(self) -> Result<TlsParameters, Error> {
        #[cfg(feature = "rustls")]
        return self.build_rustls();
        #[cfg(all(not(feature = "rustls"), feature = "native-tls"))]
        return self.build_native();
        #[cfg(all(not(feature = "rustls"), feature = "boring-tls"))]
        return self.build_boring();
    }


    #[cfg(feature = "native-tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "native-tls")))]
    pub fn build_native(self) -> Result<TlsParameters, Error> {
        let mut tls_builder = TlsConnector::builder();

        match self.cert_store {
            CertificateStore::Default => {}
            CertificateStore::None => {
                tls_builder.disable_built_in_roots(true);
            }
            #[allow(unreachable_patterns)]
            other => {
                return Err(error::tls(format!(
                    "{other:?} is not supported in native tls"
                )));
            }
        }
        for cert in self.root_certs {
            tls_builder.add_root_certificate(cert.native_tls);
        }
        tls_builder.danger_accept_invalid_hostnames(self.accept_invalid_hostnames);
        tls_builder.danger_accept_invalid_certs(self.accept_invalid_certs);

        let min_tls_version = match self.min_tls_version {
            TlsVersion::Tlsv10 => Protocol::Tlsv10,
            TlsVersion::Tlsv11 => Protocol::Tlsv11,
            TlsVersion::Tlsv12 => Protocol::Tlsv12,
            TlsVersion::Tlsv13 => {
                return Err(error::tls(
                    "min tls version Tlsv13 not supported in native tls",
                ));
            }
        };

        tls_builder.min_protocol_version(Some(min_tls_version));
        if let Some(identity) = self.identity {
            tls_builder.identity(identity.native_tls);
        }

        let connector = tls_builder.build().map_err(error::tls)?;
        Ok(TlsParameters {
            connector: InnerTlsParameters::NativeTls { connector },
            domain: self.domain,
        })
    }


    #[cfg(feature = "boring-tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boring-tls")))]
    pub fn build_boring(self) -> Result<TlsParameters, Error> {
        use boring::ssl::{SslMethod, SslVerifyMode};

        let mut tls_builder = SslConnector::builder(SslMethod::tls()).map_err(error::tls)?;

        if self.accept_invalid_certs {
            tls_builder.set_verify(SslVerifyMode::NONE);
        } else {
            match self.cert_store {
                CertificateStore::Default => {}
                CertificateStore::None => {

                    tls_builder
                        .set_cert_store_builder(X509StoreBuilder::new().map_err(error::tls)?);
                }
                #[allow(unreachable_patterns)]
                other => {
                    return Err(error::tls(format!(
                        "{other:?} is not supported in boring tls"
                    )));
                }
            }

            let cert_store = tls_builder.cert_store_mut();

            for cert in self.root_certs {
                cert_store.add_cert(cert.boring_tls).map_err(error::tls)?;
            }
        }

        if let Some(identity) = self.identity {
            tls_builder
                .set_certificate(identity.boring_tls.0.as_ref())
                .map_err(error::tls)?;
            tls_builder
                .set_private_key(identity.boring_tls.1.as_ref())
                .map_err(error::tls)?;
        }

        let min_tls_version = match self.min_tls_version {
            TlsVersion::Tlsv10 => SslVersion::TLS1,
            TlsVersion::Tlsv11 => SslVersion::TLS1_1,
            TlsVersion::Tlsv12 => SslVersion::TLS1_2,
            TlsVersion::Tlsv13 => SslVersion::TLS1_3,
        };

        tls_builder
            .set_min_proto_version(Some(min_tls_version))
            .map_err(error::tls)?;
        let connector = tls_builder.build();
        Ok(TlsParameters {
            connector: InnerTlsParameters::BoringTls {
                connector,
                accept_invalid_hostnames: self.accept_invalid_hostnames,
            },
            domain: self.domain,
        })
    }


    #[cfg(feature = "rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
    pub fn build_rustls(self) -> Result<TlsParameters, Error> {
        let just_version3 = &[&rustls::version::TLS13];
        let supported_versions = match self.min_tls_version {
            TlsVersion::Tlsv10 => {
                return Err(error::tls("min tls version Tlsv10 not supported in rustls"));
            }
            TlsVersion::Tlsv11 => {
                return Err(error::tls("min tls version Tlsv11 not supported in rustls"));
            }
            TlsVersion::Tlsv12 => rustls::ALL_VERSIONS,
            TlsVersion::Tlsv13 => just_version3,
        };

        let crypto_provider = crate::rustls_crypto::crypto_provider();
        let tls = ClientConfig::builder_with_provider(Arc::clone(&crypto_provider))
            .with_protocol_versions(supported_versions)
            .map_err(error::tls)?;


        let mut root_cert_store = RootCertStore::empty();

        #[cfg(all(
            not(feature = "rustls-platform-verifier"),
            feature = "rustls-native-certs"
        ))]
        fn load_native_roots(store: &mut RootCertStore) {
            let rustls_native_certs::CertificateResult { certs, errors, .. } =
                rustls_native_certs::load_native_certs();
            let errors_len = errors.len();

            let (added, ignored) = store.add_parsable_certificates(certs);
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "loaded platform certs with {errors_len} failing to load, {added} valid and {ignored} ignored (invalid) certs"
            );
            #[cfg(not(feature = "tracing"))]
            let _ = (errors_len, added, ignored);
        }

        #[cfg(all(feature = "rustls", feature = "webpki-roots"))]
        fn load_webpki_roots(store: &mut RootCertStore) {
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        #[cfg_attr(not(feature = "rustls-platform-verifier"), allow(unused_mut))]
        let mut extra_roots = None::<Vec<CertificateDer<'static>>>;
        match self.cert_store {
            CertificateStore::Default => {
                #[cfg(feature = "rustls-platform-verifier")]
                {
                    extra_roots = Some(Vec::new());
                }

                #[cfg(all(
                    not(feature = "rustls-platform-verifier"),
                    feature = "rustls-native-certs"
                ))]
                load_native_roots(&mut root_cert_store);

                #[cfg(all(
                    not(feature = "rustls-platform-verifier"),
                    not(feature = "rustls-native-certs"),
                    feature = "webpki-roots"
                ))]
                load_webpki_roots(&mut root_cert_store);
            }
            #[cfg(all(feature = "rustls", feature = "webpki-roots"))]
            CertificateStore::WebpkiRoots => {
                load_webpki_roots(&mut root_cert_store);
            }
            CertificateStore::None => {}
        }
        for cert in self.root_certs {
            for rustls_cert in cert.rustls {
                #[cfg(feature = "rustls-platform-verifier")]
                if let Some(extra_roots) = &mut extra_roots {
                    extra_roots.push(rustls_cert.clone());
                }
                root_cert_store.add(rustls_cert).map_err(error::tls)?;
            }
        }

        let tls = if self.accept_invalid_certs
            || (extra_roots.is_none() && self.accept_invalid_hostnames)
        {
            let verifier = InvalidCertsVerifier {
                ignore_invalid_hostnames: self.accept_invalid_hostnames,
                ignore_invalid_certs: self.accept_invalid_certs,
                roots: root_cert_store,
                crypto_provider,
            };
            tls.dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
        } else {
            #[cfg(feature = "rustls-platform-verifier")]
            if let Some(extra_roots) = extra_roots {
                tls.dangerous().with_custom_certificate_verifier(Arc::new(
                    rustls_platform_verifier::Verifier::new_with_extra_roots(
                        extra_roots,
                        crypto_provider,
                    )
                    .map_err(error::tls)?,
                ))
            } else {
                tls.with_root_certificates(root_cert_store)
            }

            #[cfg(not(feature = "rustls-platform-verifier"))]
            {
                tls.with_root_certificates(root_cert_store)
            }
        };

        let tls = if let Some(identity) = self.identity {
            let (client_certificates, private_key) = identity.rustls_tls;
            tls.with_client_auth_cert(client_certificates, private_key)
                .map_err(error::tls)?
        } else {
            tls.with_no_client_auth()
        };

        Ok(TlsParameters {
            connector: InnerTlsParameters::Rustls {
                config: Arc::new(tls),
            },
            domain: self.domain,
        })
    }
}

#[derive(Clone)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum InnerTlsParameters {
    #[cfg(feature = "native-tls")]
    NativeTls { connector: TlsConnector },
    #[cfg(feature = "rustls")]
    Rustls { config: Arc<ClientConfig> },
    #[cfg(feature = "boring-tls")]
    BoringTls {
        connector: SslConnector,
        accept_invalid_hostnames: bool,
    },
}

impl TlsParameters {


    #[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
    )]
    pub fn new(domain: String) -> Result<Self, Error> {
        TlsParametersBuilder::new(domain).build()
    }


    pub fn builder(domain: String) -> TlsParametersBuilder {
        TlsParametersBuilder::new(domain)
    }


    #[cfg(feature = "native-tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "native-tls")))]
    pub fn new_native(domain: String) -> Result<Self, Error> {
        TlsParametersBuilder::new(domain).build_native()
    }


    #[cfg(feature = "rustls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rustls")))]
    pub fn new_rustls(domain: String) -> Result<Self, Error> {
        TlsParametersBuilder::new(domain).build_rustls()
    }


    #[cfg(feature = "boring-tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boring-tls")))]
    pub fn new_boring(domain: String) -> Result<Self, Error> {
        TlsParametersBuilder::new(domain).build_boring()
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
}


#[derive(Clone)]
#[allow(missing_copy_implementations)]
#[cfg_attr(
    not(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")),
    deprecated(
        note = "starting from lettre v0.12 `Certificate` won't be available when none of the TLS backends are enabled"
    )
)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
)]
pub struct Certificate {
    #[cfg(feature = "native-tls")]
    native_tls: native_tls::Certificate,
    #[cfg(feature = "rustls")]
    rustls: Vec<CertificateDer<'static>>,
    #[cfg(feature = "boring-tls")]
    boring_tls: boring::x509::X509,
}

#[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
impl Certificate {

    pub fn from_der(der: Vec<u8>) -> Result<Self, Error> {
        #[cfg(feature = "native-tls")]
        let native_tls_cert = native_tls::Certificate::from_der(&der).map_err(error::tls)?;

        #[cfg(feature = "boring-tls")]
        let boring_tls_cert = boring::x509::X509::from_der(&der).map_err(error::tls)?;

        Ok(Self {
            #[cfg(feature = "native-tls")]
            native_tls: native_tls_cert,
            #[cfg(feature = "rustls")]
            rustls: vec![der.into()],
            #[cfg(feature = "boring-tls")]
            boring_tls: boring_tls_cert,
        })
    }


    pub fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        #[cfg(feature = "native-tls")]
        let native_tls_cert = native_tls::Certificate::from_pem(pem).map_err(error::tls)?;

        #[cfg(feature = "boring-tls")]
        let boring_tls_cert = boring::x509::X509::from_pem(pem).map_err(error::tls)?;

        #[cfg(feature = "rustls")]
        let rustls_cert = {
            CertificateDer::pem_slice_iter(pem)
                .collect::<Result<Vec<_>, pki_types::pem::Error>>()
                .map_err(|_| error::tls("invalid certificates"))?
        };

        Ok(Self {
            #[cfg(feature = "native-tls")]
            native_tls: native_tls_cert,
            #[cfg(feature = "rustls")]
            rustls: rustls_cert,
            #[cfg(feature = "boring-tls")]
            boring_tls: boring_tls_cert,
        })
    }
}

impl Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate").finish()
    }
}


#[allow(missing_copy_implementations)]
#[cfg_attr(
    not(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")),
    deprecated(
        note = "starting from lettre v0.12 `Identity` won't be available when none of the TLS backends are enabled"
    )
)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls")))
)]
pub struct Identity {
    #[cfg(feature = "native-tls")]
    native_tls: native_tls::Identity,
    #[cfg(feature = "rustls")]
    rustls_tls: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    #[cfg(feature = "boring-tls")]
    boring_tls: (boring::x509::X509, PKey<boring::pkey::Private>),
}

impl Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity").finish()
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Identity {
            #[cfg(feature = "native-tls")]
            native_tls: self.native_tls.clone(),
            #[cfg(feature = "rustls")]
            rustls_tls: (self.rustls_tls.0.clone(), self.rustls_tls.1.clone_key()),
            #[cfg(feature = "boring-tls")]
            boring_tls: (self.boring_tls.0.clone(), self.boring_tls.1.clone()),
        }
    }
}

#[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]
impl Identity {
    pub fn from_pem(pem: &[u8], key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            #[cfg(feature = "native-tls")]
            native_tls: Identity::from_pem_native_tls(pem, key)?,
            #[cfg(feature = "rustls")]
            rustls_tls: Identity::from_pem_rustls_tls(pem, key)?,
            #[cfg(feature = "boring-tls")]
            boring_tls: Identity::from_pem_boring_tls(pem, key)?,
        })
    }

    #[cfg(feature = "native-tls")]
    fn from_pem_native_tls(pem: &[u8], key: &[u8]) -> Result<native_tls::Identity, Error> {
        native_tls::Identity::from_pkcs8(pem, key).map_err(error::tls)
    }

    #[cfg(feature = "rustls")]
    fn from_pem_rustls_tls(
        pem: &[u8],
        key: &[u8],
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Error> {
        let key = match PrivateKeyDer::from_pem_slice(key) {
            Ok(key) => key,
            Err(pki_types::pem::Error::NoItemsFound) => {
                return Err(error::tls("no private key found"));
            }
            Err(err) => return Err(error::tls(err)),
        };

        Ok((vec![pem.to_owned().into()], key))
    }

    #[cfg(feature = "boring-tls")]
    fn from_pem_boring_tls(
        pem: &[u8],
        key: &[u8],
    ) -> Result<(boring::x509::X509, PKey<boring::pkey::Private>), Error> {
        let cert = boring::x509::X509::from_pem(pem).map_err(error::tls)?;
        let key = boring::pkey::PKey::private_key_from_pem(key).map_err(error::tls)?;
        Ok((cert, key))
    }
}

#[cfg(feature = "rustls")]
#[derive(Debug)]
struct InvalidCertsVerifier {
    ignore_invalid_hostnames: bool,
    ignore_invalid_certs: bool,
    roots: RootCertStore,
    crypto_provider: Arc<CryptoProvider>,
}

#[cfg(feature = "rustls")]
impl ServerCertVerifier for InvalidCertsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        if !self.ignore_invalid_certs {
            rustls::client::verify_server_cert_signed_by_trust_anchor(
                &cert,
                &self.roots,
                intermediates,
                now,
                self.crypto_provider.signature_verification_algorithms.all,
            )?;
        }

        if !self.ignore_invalid_hostnames {
            rustls::client::verify_server_name(&cert, server_name)?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
