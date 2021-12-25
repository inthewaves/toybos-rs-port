use crate::utils::posix_macros::{S_ISBLK, S_ISCHR, S_ISDIR, S_ISFIFO, S_ISLNK, S_ISSOCK};
use libc::stat;
use std::ffi::{CStr, OsStr, OsString};
use std::os::raw::c_char;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

// dirtree.rs

// Values returnable from callback function (bitfield, or them together)
// Default with no callback is 0

/// Add this node to the tree
pub const DIRTREE_SAVE: i32 = 1;

// Recurse into children
pub const DIRTREE_RECURSE: i32 = 2;

// Call again after handling all children of this directory
// (Ignored for non-directories, sets linklen = -1 before second call.)
pub const DIRTREE_COMEAGAIN: i32 = 4;

/// Follow symlinks to directories
pub const DIRTREE_SYMFOLLOW: i32 = 8;

// Don't warn about failure to stat
pub const DIRTREE_SHUTUP: i32 = 16;

// skip non-numeric entries
pub const DIRTREE_PROC: i32 = 64;

// Return files we can't stat
pub const DIRTREE_STATLESS: i32 = 128;

// Don't look at any more files in this directory.
pub const DIRTREE_ABORT: i32 = 256;

// Not needed
// pub const DIRTREE_ABORTVAL: i32 = -1;

/// See toybox/lib.h
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Hash)]
pub struct dirtree {
    //pub next: Option<Box<dirtree>>,
    //pub parent: Option<Box<dirtree>>,
    //pub child: Vec<Box<dirtree>>,
    /// place for user to store their stuff (can be pointer)
    pub extra: i64,
    pub symlink: Option<String>,
    pub dirfd: PathBuf,
    pub st: stat,
    pub again: i8,
    // TODO: PathBuf
    pub name: Option<String>,
}

/// From regcomp(3):
///
/// # POSIX regex matching
/// `regexec()` is used to match a null-terminated string against the precompiled pattern buffer,
/// `preg`. `nmatch` and `pmatch` are used to provide information regarding the location of any
/// matches. `cflags` may be the bitwise-or of one or both of `REG_NOTBOL` and `REG_NOTEOL` which
/// cause changes in matching behavior described below.
///
/// * `REG_NOTBOL`
///
///   The match-beginning-of-line operator always fails to match  (but
///   see  the  compilation flag `REG_NEWLINE` above).  This flag may be
///   used when different portions of a string are passed to `regexec()`
///   and the beginning of the string should not be interpreted as the
///   beginning of the line.
///
/// * `REG_NOTEOL`
///
///   The match-end-of-line operator always fails to  match  (but  see
///   the compilation flag `REG_NEWLINE` above).
///
/// # Byte offsets
///
/// Unless `REG_NOSUB` was set for the compilation of the pattern buffer, it
/// is possible to obtain match addressing information. `pmatch` must be di‐
/// mensioned  to  have  at  least `nmatch` elements.  These are filled in by
/// regexec() with substring match addresses.  The offsets  of  the  subexpression
/// starting at the ith open parenthesis are stored in `pmatch[i]`.
/// The  entire  regular  expression's  match  addresses  are   stored   in
/// `pmatch[0]`.   (Note  that  to  return  the  offsets  of  N subexpression
/// matches, `nmatch` must be at least `N+1`.)  Any unused  structure  elements
/// will contain the value `-1`.
///
/// # Return value
/// Returns zero for a successful match or `REG_NOMATCH` for failure.
pub fn regexec0(
    preg: *const libc::regex_t,
    string: &OsStr,
    len: i64,
    nmatch: i32,
    pmatch: &mut libc::regmatch_t,
    eflags: i32,
) -> i32 {
    let mut backup = libc::regmatch_t { rm_so: 0, rm_eo: 0 };
    let mut pmatch = if nmatch == 0 { &mut backup } else { pmatch };
    pmatch.rm_so = 0;
    pmatch.rm_eo = len as i32;

    // Don't use a CString, because nul characters are valid. The `len` parameter is what is
    // used for marking the end.
    // We should expect to get something, because regex is not empty.
    let input: Vec<u8> = {
        let mut buf: Vec<u8> = string.as_bytes().to_vec();
        // Needs NUL termination. This is an issue with KLEE.
        if buf.len() == 0 || buf[buf.len() - 1] != 0 {
            buf.push(0);
        }
        buf
    };

    // Unsafe Rust is needed here because Toybox uses this system call specifically.
    unsafe {
        libc::regexec(
            preg,
            // SAFETY: u8 can be interpreted as c_char = i8, since we are in the context of bytes.
            input.as_ptr() as *const c_char,
            nmatch as usize,
            pmatch,
            eflags | libc::REG_STARTEND,
        )
    }
}

pub fn getusername(uid: libc::uid_t) -> OsString {
    let mut buffer = vec![0; 256];
    // Using unsafe Rust, since username can only be received with system calls.
    let mut passwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut temp: *mut libc::passwd = std::ptr::null_mut();
    loop {
        match buffer.len().checked_mul(2) {
            None => return OsString::from(uid.to_string()),
            Some(new_len) => buffer.resize(new_len, 0),
        }
        let getpwuid_errno = unsafe {
            libc::getpwuid_r(
                uid,
                &mut passwd,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut temp,
            )
        };
        if getpwuid_errno != libc::ERANGE {
            break;
        }
    }

    // From getpwnam(3):
    //  The getpwnam_r() and getpwuid_r() functions obtain the same information
    //  as  getpwnam() and getpwuid(), but store the retrieved passwd structure
    //  in the space pointed to by pwd.  The string fields pointed  to  by  the
    //  members  of  the  passwd structure are stored in the buffer buf of size
    //  buflen.  A pointer to the result (in case of success) or NULL (in  case
    //  no entry was found or an error occurred) is stored in *result.
    if temp.is_null() || temp != &mut passwd {
        OsString::from(uid.to_string())
    } else {
        OsString::from_vec(
            unsafe { CStr::from_ptr(passwd.pw_name) }
                .to_bytes()
                .to_vec(),
        )
    }
}

pub fn getgroupname(gid: libc::gid_t) -> OsString {
    let mut buffer = vec![0; 256];
    // Using unsafe Rust, since username can only be received with system calls.
    let mut group = unsafe { std::mem::zeroed::<libc::group>() };
    let mut temp: *mut libc::group = std::ptr::null_mut();

    loop {
        match buffer.len().checked_mul(2) {
            None => return OsString::from(gid.to_string()),
            Some(new_len) => buffer.resize(new_len, 0),
        }
        let getgrgid_errno = unsafe {
            libc::getgrgid_r(
                gid,
                &mut group,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut temp,
            )
        };
        if getgrgid_errno != libc::ERANGE {
            break;
        }
    }

    if temp.is_null() || temp != &mut group {
        OsString::from(gid.to_string())
    } else {
        OsString::from_vec(unsafe { CStr::from_ptr(group.gr_name) }.to_bytes().to_vec())
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct HumanReadableStyle {
    /// Corresponds to HR_SPACE
    pub space_between_num_units: bool,
    /// Corresponds to HR_B
    pub use_B_for_single_byte_units: bool,
    /// Corresponds to HR_1000
    pub use_decimal_instead_of_bin_digits: bool,
    /// Corresponds to HR_NODOT
    pub no_tenths_for_single_digit_units: bool,
}

/// display first "dgt" many digits of number plus unit (kilo-exabytes)
pub fn human_readable_long(num: u64, dgt: i32, unit: i32, style: &HumanReadableStyle) -> String {
    let mut snap = 0u64;
    let divisor = if style.use_decimal_instead_of_bin_digits {
        1000
    } else {
        1024
    };

    // Divide rounding up until we have 3 or fewer digits. Since the part we
    // print is decimal, the test is 999 even when we divide by 1024.
    // The largest unit we can detect is 1<<64 = 18 Exabytes, but we added
    // Zettabyte and Yottabyte in case "unit" starts above zero.
    let mut unit = unit as usize;
    let mut num = num;
    let mut len;
    loop {
        len = num.to_string().len() as u64;
        if len <= dgt as u64 {
            break;
        }
        snap = num;
        num = ((num) + (divisor / 2)) / divisor;
        unit += 1;
    }
    // if (CFG_TOYBOX_DEBUG && unit>8) return sprintf(buf, "%.*s", dgt, "TILT");

    let mut buf = if !style.no_tenths_for_single_digit_units && unit != 0 && len == 1 {
        // Redo rounding for 1.2M case, this works with and without HR_1000.
        num = snap / divisor;
        snap -= num * divisor;
        snap = ((snap * 100) + 50) / divisor;
        snap /= 10;
        format!("{}.{}", num, snap)
    } else {
        num.to_string()
    };
    if style.space_between_num_units {
        buf.push(' ');
    }
    if unit != 0 {
        // O(n) since it uses an iterator, but effectively constant time since static String size
        // is constant.
        let mut unit_char = " kMGTPEZY".chars().nth(unit).unwrap();
        if !style.use_decimal_instead_of_bin_digits {
            unit_char.make_ascii_uppercase();
        }
        buf.push(unit_char);
    } else if style.use_B_for_single_byte_units {
        buf.push('B');
    }

    buf
}

/// Give 3 digit estimate + units ala 999M or 1.7T
pub fn human_readable(num: u64, style: &HumanReadableStyle) -> String {
    human_readable_long(num, 3, 0, style)
}

/// Format access mode into a drwxrwxrwx string
pub fn mode_to_string(mode: u32) -> String {
    let mut buf = String::new();

    for i in 0..9 {
        let bit = mode & (1 << i);
        let c = i % 3;
        let d = i / 3;

        let char: char = if c == 0 && (mode & (1 << (d + 9))) != 0 {
            let tmp_char = "tss".chars().nth(d as usize).unwrap();
            if bit == 0 {
                ((tmp_char as u8) & !0x20) as char
            } else {
                tmp_char
            }
        } else if bit != 0 {
            "xwr".chars().nth(c).unwrap()
        } else {
            '-'
        };

        buf = char.to_string() + &*buf;
    }
    buf.insert(
        0,
        if S_ISDIR(mode) {
            'd'
        } else if S_ISBLK(mode) {
            'b'
        } else if S_ISCHR(mode) {
            'c'
        } else if S_ISLNK(mode) {
            'l'
        } else if S_ISFIFO(mode) {
            'p'
        } else if S_ISSOCK(mode) {
            's'
        } else {
            '-'
        },
    );

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_readable_tests() {
        assert_eq!(
            "118M",
            human_readable_long(123456789, 3, 0, &HumanReadableStyle::default())
        );
        assert_eq!(
            "123M",
            human_readable_long(
                123456789,
                3,
                0,
                &HumanReadableStyle {
                    use_decimal_instead_of_bin_digits: true,
                    ..Default::default()
                }
            )
        );
        assert_eq!(
            "5.5K",
            human_readable_long(5675, 3, 0, &HumanReadableStyle::default())
        );
        assert_eq!(
            "5.6k",
            human_readable_long(
                5675,
                3,
                0,
                &HumanReadableStyle {
                    use_decimal_instead_of_bin_digits: true,
                    ..Default::default()
                }
            )
        );

        // An example input where we give a better result than coreutils.
        // 267350/1024=261.08. We say 261K and coreutils says 262K.
        assert_eq!(
            "261K",
            human_readable_long(267350, 3, 0, &HumanReadableStyle::default())
        );

        assert_eq!(
            "123B",
            human_readable_long(
                123,
                3,
                0,
                &HumanReadableStyle {
                    use_B_for_single_byte_units: true,
                    ..Default::default()
                }
            )
        );
        assert_eq!(
            "118M",
            human_readable_long(
                123456789,
                3,
                0,
                &HumanReadableStyle {
                    use_B_for_single_byte_units: true,
                    ..Default::default()
                }
            )
        );
        assert_eq!(
            "118 M",
            human_readable_long(
                123456789,
                3,
                0,
                &HumanReadableStyle {
                    space_between_num_units: true,
                    ..Default::default()
                }
            )
        );
        assert_eq!(
            "118 M",
            human_readable_long(
                123456789,
                3,
                0,
                &HumanReadableStyle {
                    space_between_num_units: true,
                    use_B_for_single_byte_units: true,
                    ..Default::default()
                }
            )
        );
    }
}
