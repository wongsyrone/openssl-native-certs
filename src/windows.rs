use crate::RootStoreBuilder;
use schannel;
use std::io::{Error, ErrorKind};

pub fn build_native_certs<B: RootStoreBuilder>(builder: &mut B) -> Result<(), Error> {
    let mut first_error = None;

    let store = schannel::cert_store::CertStore::open_current_user("ROOT")?;

    for cert in store.certs() {
        match builder.load_der(cert.to_der()) {
            Err(err) => {
                first_error = first_error.or_else(|| Some(Error::new(ErrorKind::InvalidData, err)));
            }
            _ => {}
        };
    }

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(())
    }
}
