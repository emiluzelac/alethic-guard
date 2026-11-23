use crate::GuardResult;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

const MAX_FRAME: u64 = 65_536;

pub fn configure(stream: &UnixStream) -> GuardResult<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    Ok(())
}

pub fn read_frame<T: DeserializeOwned>(stream: &UnixStream) -> GuardResult<T> {
    let mut input = BufReader::new(stream.take(MAX_FRAME + 1));
    let mut frame = Vec::new();
    input.read_until(b'\n', &mut frame)?;
    if frame.last() != Some(&b'\n') || frame.len() as u64 > MAX_FRAME {
        return Err("invalid frame size or delimiter".into());
    }
    Ok(serde_json::from_slice(&frame)?)
}

pub fn write_frame(stream: &mut UnixStream, value: &impl Serialize) -> GuardResult<()> {
    let mut body = serde_json::to_vec(value)?;
    if body.len() as u64 >= MAX_FRAME {
        return Err("response exceeds maximum frame size".into());
    }
    body.push(b'\n');
    stream.write_all(&body)?;
    Ok(())
}
