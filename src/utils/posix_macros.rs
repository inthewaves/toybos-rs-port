pub fn S_ISLNK(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFLNK
}

pub fn S_ISDIR(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFDIR
}

pub fn S_ISBLK(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFBLK
}

pub fn S_ISCHR(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFCHR
}

pub fn S_ISFIFO(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFIFO
}

pub fn S_ISSOCK(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFSOCK
}

/// Is it a regular file?
pub fn S_ISREG(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFREG
}
