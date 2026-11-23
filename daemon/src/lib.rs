pub mod artifact;
pub mod auth;
pub mod broker;
pub mod collector;
pub mod effect;
pub mod emergency;
pub mod evidence;
pub mod gateway_process;
pub mod lifecycle;
pub mod network;
pub mod policy;
pub mod protocol;
pub mod vm;

pub type GuardResult<T> = Result<T, Box<dyn std::error::Error>>;

pub fn digest_file(path: &std::path::Path) -> GuardResult<String> {
    use sha2::{Digest, Sha256};
    let mut source = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    std::io::copy(&mut source, &mut digest)?;
    Ok(format!("sha256:{:x}", digest.finalize()))
}
