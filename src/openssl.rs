use openssl::x509::store::X509StoreBuilderRef;
use openssl::x509::X509;

use crate::RootStoreBuilder;
use std::io::BufRead;
use std::io::{Error, ErrorKind};

/// Loads root certificates found in the platform's native certificate
/// store.
///
/// On success, this returns a `rustls::RootCertStore` loaded with a
/// snapshop of the root certificates found on this platform.  This
/// function fails in a platform-specific way, expressed in a `std::io::Error`.
///
/// This function can be expensive: on some platforms it involves loading
/// and parsing a ~300KB disk file.  It's therefore prudent to call
/// this sparingly.
///
pub fn load_native_certs(dst: &mut X509StoreBuilderRef) -> Result<(), Error> {
    // newtype pattern
    struct RootCertStoreLoader<'a> {
        store: &'a mut X509StoreBuilderRef,
    }

    impl<'a> RootStoreBuilder for RootCertStoreLoader<'a> {
        fn load_der(&mut self, der: &[u8]) -> std::result::Result<(), Error> {
            let cert = X509::from_der(der)?;
            self.store.add_cert(cert)?;
            Ok(())
        }

        fn load_pem(&mut self, pem: &[u8]) -> std::result::Result<(), Error> {
            let cert = X509::from_pem(pem)?;
            self.store.add_cert(cert)?;
            Ok(())
        }
    }

    let mut loader = RootCertStoreLoader { store: dst };
    crate::build_native_certs(&mut loader)
}
