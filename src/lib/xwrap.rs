use std::ffi::{CString, OsStr, OsString};
use std::io::BufRead;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::process::exit;

/// Put string with length (does not append newline)
pub fn xputl(s: &OsStr, len: u32) {
    xputl_bytes(s.as_bytes(), len);
}

pub fn xregcomp(preg: *mut libc::regex_t, regex: &OsStr, cflags: i32) {
    let mut cflags = cflags;

    // BSD regex implementations don't support the empty regex (which isn't
    // allowed in the POSIX grammar), but glibc does. Fake it for BSD.
    let regex_cstr: Vec<u8> = if regex.is_empty() || regex.as_bytes().starts_with(&[0]) {
        cflags |= libc::REG_EXTENDED;
        vec![b'(', b')', 0].to_owned()
    } else {
        // We should expect to get something, because regex is not empty.
        let mut vec: Vec<u8> = regex.as_bytes().to_vec();
        // Needs NUL termination.
        if vec.len() == 0 || vec[vec.len() - 1] != 0 {
            vec.push(0);
        }
        vec
    };

    // Unsafe Rust is needed to compile regex so that it behaves like Toybox, since Toybox also
    // uses these Linux APIs. There are crates for regex, but they're missing some features, e.g.
    // they don't have extended regex toggles, for example.
    let rc = unsafe {
        libc::regcomp(
            preg,
            // Safe, as u8 can just be interpreted as c_char = i8, since this is in context of bytes
            regex_cstr.as_ptr() as *const c_char,
            cflags)
    };
    if rc != 0 {
        let mut libbuf = vec![0; 4096];
        // Unsafe Rust is needed to get errors from the OS like Toybox.
        unsafe { libc::regerror(rc, preg, libbuf.as_mut_ptr(), libbuf.len()) };

        let err = match libbuf
            .iter()
            .map(|c| *c as u8)
            .collect::<Vec<u8>>()
            .split(|chr| *chr == 0)
            .next()
        {
            Some(char) => String::from_utf8_lossy(char).to_string(),
            None => String::from("Unknown"),
        };
        eprintln!("grep: bad regex '{}': {}", regex.to_string_lossy(), err);
        exit(1);
    }
}

/// Put string with length (does not append newline)
pub fn xputl_bytes(s: &[u8], len: u32) {
    let trim_len = if len >= s.len() as u32 {
        s.len()
    } else {
        len as usize
    };
    print_nonklee!("{}", String::from_utf8_lossy(&s[0..trim_len]));
}
