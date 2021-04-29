//! openssl-native-certs allows openssl to use the platform's native certificate
//! store when operating as a TLS client.

#[cfg(all(unix, not(target_os = "macos")))]
mod unix;
#[cfg(all(unix, not(target_os = "macos")))]
use unix as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

use std::io::Error;
use std::io::BufRead;

pub trait RootStoreBuilder {
    fn load_der(&mut self, der: Vec<u8>) -> Result<(), Error>;
    fn load_pem_file(&mut self, rd: &mut dyn BufRead) -> Result<(), Error>;
}

/// Loads root certificates found in the platform's native certificate
/// store, executing callbacks on the provided builder.
///
/// This function fails in a platform-specific way, expressed in a `std::io::Error`.
///
/// This function can be expensive: on some platforms it involves loading
/// and parsing a ~300KB disk file.  It's therefore prudent to call
/// this sparingly.
pub fn build_native_certs<B: RootStoreBuilder>(builder: &mut B) -> Result<(), Error> {
    platform::build_native_certs(builder)
}
