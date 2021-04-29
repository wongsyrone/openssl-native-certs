use openssl::x509::{store::X509StoreBuilderRef, X509};

use crate::RootStoreBuilder;
use std::io::Error;

/// Loads root certificates found in the platform's native certificate
/// store.
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
