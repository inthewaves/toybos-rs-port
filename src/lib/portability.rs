// Various constants old build environments might not have even if kernel does

pub const AT_FDCWD: i32 = -100;

pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

pub fn dev_major(dev: u32) -> u32 {
    // Toybox is returning a normal C int... so u32 it is.
    (match std::env::consts::OS {
        "linux" => (dev & 0xfff00) >> 8,
        "macos" => (dev >> 24) & 0xff,
        "openbsd" => {
            // see makedev(3) (https://man.openbsd.org/major.3)
            nix::sys::stat::major(dev as u64) as u32
        }
        _ => {
            panic!("Toybox doesn't implement dev_major for this platform")
        }
    }) as u32
}

pub fn dev_minor(dev: u32) -> u32 {
    // Toybox is returning a normal C int... so u32 it is.
    (match std::env::consts::OS {
        "linux" => ((dev & 0xfff00000) >> 12) | (dev & 0xff),
        "macos" => dev & 0xffffff,
        "openbsd" => {
            // see makedev(3) (https://man.openbsd.org/minor.3)
            nix::sys::stat::minor(dev as u64) as u32
        }
        _ => {
            panic!("Toybox doesn't implement dev_minor for this platform")
        }
    }) as u32
}
