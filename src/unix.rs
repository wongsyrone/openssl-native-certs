use crate::RootStoreBuilder;
use openssl_probe;
use std::{
    fs::File,
    io::{Error, ErrorKind},
    path::Path,
};

fn load_file(builder: &mut impl RootStoreBuilder, path: &Path) -> Result<(), Error> {
    let mut f = File::open(&path)?;
    let mut buf: Vec<u8> = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut buf)?;
    if builder.load_pem(&buf).is_err() {
        Err(Error::new(
            ErrorKind::InvalidData,
            format!("Could not load PEM file {:?}", path),
        ))
    } else {
        Ok(())
    }
}

pub fn build_native_certs<B: RootStoreBuilder>(builder: &mut B) -> Result<(), Error> {
    let likely_locations = openssl_probe::probe();
    let mut first_error = None;

    if let Some(file) = likely_locations.cert_file {
        match load_file(builder, &file) {
            Err(err) => {
                first_error = first_error.or_else(|| Some(err));
            }
            _ => {}
        }
    }

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(())
    }
}
