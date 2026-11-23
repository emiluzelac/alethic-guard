use std::{
    io, mem,
    os::{fd::AsRawFd, unix::net::UnixStream},
};

pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut creds: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SO_PEERCRED returns the kernel's credential snapshot from connect().
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut creds as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(len).ok() != Some(mem::size_of::<libc::ucred>()) {
        return Err(io::Error::other("unexpected peer credentials"));
    }
    Ok(creds.uid)
}
