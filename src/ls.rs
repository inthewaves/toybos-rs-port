#![feature(osstring_ascii)]
#![allow(non_snake_case, non_upper_case_globals)]

use std::cmp::Ordering;
use std::env::args_os;
use std::fmt::Display;
use std::fs;
use std::fs::Metadata;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt as UnixMetadataExt};
use std::path::{Path, PathBuf};
use std::process::exit;

use chrono::{Local, TimeZone, Timelike};
use nix::errno::errno;
use nix::NixPath;
use structopt::StructOpt;

use crate::lib::lib::{
    getgroupname, getusername, human_readable, mode_to_string, HumanReadableStyle, DIRTREE_ABORT,
    DIRTREE_RECURSE, DIRTREE_SAVE,
};
use crate::lib::lsm::{lsm_get_context, lsm_lget_context};
use crate::lib::portability::{dev_major, dev_minor};
use crate::tree::map_tree::{MapTree, Node, TreeIdx};
use crate::utils::posix_macros::{S_ISBLK, S_ISCHR, S_ISDIR, S_ISFIFO, S_ISLNK, S_ISREG, S_ISSOCK};

#[cfg(feature = "verifier-klee")]
use verification_annotations::prelude::*;

mod lib;
mod tree;
mod utils;

#[derive(Debug, StructOpt)]
#[structopt(name = "ls", about = "List files.")]
struct Flag {
    //
    // What to show:
    //
    /// all files including .hidden
    #[structopt(short = "a")]
    a_all: bool,
    /// escape nongraphic chars
    #[structopt(short = "b")]
    b_escape_nongraphic_chars: bool,
    #[structopt(long = "show-control-chars")]
    show_control_chars: bool,
    /// use ctime for timestamps
    #[structopt(short = "c")]
    c_ctime: bool,
    /// directory, not contents
    #[structopt(short = "d")]
    d_directory: bool,
    /// inode number
    #[structopt(short = "i")]
    i_inode: bool,
    /// put a '/' after dir names
    #[structopt(short = "p")]
    p_slash_dir_name: bool,
    /// unprintable chars as '?'
    #[structopt(short = "q")]
    q_unprintable_chars: bool,
    /// storage used (1024 byte units)
    #[structopt(short = "s")]
    s_storage_used: bool,
    /// use access time for timestamps
    #[structopt(short = "u")]
    u_access_time: bool,
    /// list all files but . and ..
    #[structopt(short = "A")]
    A_list_all: bool,
    /// follow command line symlinks
    #[structopt(short = "H")]
    H_follow_cli_symlinks: bool,
    /// follow symlinks
    #[structopt(short = "L")]
    L_follow_symlinks: bool,
    /// recursively list in subdirs
    #[structopt(short = "R")]
    R_recursive: bool,
    /// append /dir *exe @sym |FIFO
    #[structopt(short = "F")]
    F_append: bool,
    /// Display SELinux contexts
    #[structopt(short = "Z")]
    Z_security_ctx: bool,

    //
    // Output formats:
    //
    #[structopt(short = "1")]
    one_file_per_line: bool,
    /// columns (sorted vertically)
    #[structopt(short = "C")]
    C_columns_vert_sort: bool,
    /// like -l but no owner
    #[structopt(short = "g")]
    g_long_no_owner: bool,
    #[structopt(short = "h")]
    h_human_readable_sizes: bool,
    #[structopt(short = "k")]
    k: bool,
    /// long (show full details)
    #[structopt(short = "l")]
    l_long: bool,
    /// show long output with full time
    #[structopt(long = "full-time")]
    full_time: bool,
    #[structopt(short = "m")]
    m_comma_separated: bool,
    /// like -l but numeric uid/gid
    #[structopt(short = "n")]
    n_long_numeric_ids: bool,
    /// like -l but no group
    #[structopt(short = "o")]
    o_long_no_group: bool,
    /// set column width
    #[structopt(short = "w")]
    w_column_width: Option<u32>,
    /// columns (horizontally sort)
    #[structopt(short = "x")]
    x_columns_horiz_sort: bool,
    #[structopt(long)]
    color: Option<String>,

    //
    // sorting (default is alphabetical)
    //
    #[structopt(short = "f")]
    f_unsorted: bool,
    #[structopt(short = "r")]
    r_reverse: bool,
    #[structopt(short = "t")]
    t_timestamp: bool,
    #[structopt(short = "S")]
    S_size: bool,
    args: Vec<PathBuf>,
    /// The bitfield of flags, determined via the constants [FLAG_1], [FLAG_x], etc.
    #[structopt(skip)]
    optflags: i64,
}

#[cfg(feature = "verifier-klee")]
impl Flag {
    fn abstract_value() -> Self {
        use verification_annotations::prelude::*;

        let column_width = u32::abstract_value();
        verifier::assume(0 <= column_width && column_width <= 1000);
        let column_width_option = match column_width {
            1000 => None,
            x => Some(x),
        };

        Flag {
            a_all: bool::abstract_value(),
            b_escape_nongraphic_chars: bool::abstract_value(),
            show_control_chars: bool::abstract_value(),
            c_ctime: bool::abstract_value(),
            d_directory: bool::abstract_value(),
            i_inode: bool::abstract_value(),
            p_slash_dir_name: bool::abstract_value(),
            q_unprintable_chars: bool::abstract_value(),
            s_storage_used: bool::abstract_value(),
            u_access_time: bool::abstract_value(),
            A_list_all: bool::abstract_value(),
            H_follow_cli_symlinks: bool::abstract_value(),
            L_follow_symlinks: bool::abstract_value(),
            R_recursive: bool::abstract_value(),
            F_append: bool::abstract_value(),
            Z_security_ctx: bool::abstract_value(),
            one_file_per_line: bool::abstract_value(),
            C_columns_vert_sort: bool::abstract_value(),
            g_long_no_owner: bool::abstract_value(),
            h_human_readable_sizes: bool::abstract_value(),
            k: bool::abstract_value(),
            l_long: bool::abstract_value(),
            full_time: bool::abstract_value(),
            m_comma_separated: bool::abstract_value(),
            n_long_numeric_ids: bool::abstract_value(),
            o_long_no_group: bool::abstract_value(),
            w_column_width: column_width_option,
            x_columns_horiz_sort: bool::abstract_value(),
            color: None,
            f_unsorted: bool::abstract_value(),
            r_reverse: bool::abstract_value(),
            t_timestamp: bool::abstract_value(),
            S_size: bool::abstract_value(),
            args: vec![],
            optflags: 0,
        }
    }
}

///
/// From generated/flags.h
/// Run the replacement rule: Replace
///     (#define (FLAG_.*) \((1<<\d*)\))
/// with
///     $1\nconst $2: i64 = $3;
/// Then let `rustfmt` do its thing.
///
// #ifdef FOR_ls
// #ifndef TT
// #define TT this.ls
// #endif
// #define FLAG_1 (1<<0)
const FLAG_1: i64 = 1 << 0;
// #define FLAG_x (1<<1)
const FLAG_x: i64 = 1 << 1;
// #define FLAG_w (1<<2)
const FLAG_w: i64 = 1 << 2;
// #define FLAG_u (1<<3)
const FLAG_u: i64 = 1 << 3;
// #define FLAG_t (1<<4)
const FLAG_t: i64 = 1 << 4;
// #define FLAG_s (1<<5)
const FLAG_s: i64 = 1 << 5;
// #define FLAG_r (1<<6)
const FLAG_r: i64 = 1 << 6;
// #define FLAG_q (1<<7)
const FLAG_q: i64 = 1 << 7;
// #define FLAG_p (1<<8)
const FLAG_p: i64 = 1 << 8;
// #define FLAG_n (1<<9)
const FLAG_n: i64 = 1 << 9;
// #define FLAG_m (1<<10)
const FLAG_m: i64 = 1 << 10;
// #define FLAG_l (1<<11)
const FLAG_l: i64 = 1 << 11;
// #define FLAG_k (1<<12)
const FLAG_k: i64 = 1 << 12;
// #define FLAG_i (1<<13)
const FLAG_i: i64 = 1 << 13;
// #define FLAG_h (1<<14)
const FLAG_h: i64 = 1 << 14;
// #define FLAG_f (1<<15)
const FLAG_f: i64 = 1 << 15;
// #define FLAG_d (1<<16)
const FLAG_d: i64 = 1 << 16;
// #define FLAG_c (1<<17)
const FLAG_c: i64 = 1 << 17;
// #define FLAG_b (1<<18)
const FLAG_b: i64 = 1 << 18;
// #define FLAG_a (1<<19)
const FLAG_a: i64 = 1 << 19;
// #define FLAG_S (1<<20)
const FLAG_S: i64 = 1 << 20;
// #define FLAG_R (1<<21)
const FLAG_R: i64 = 1 << 21;
// #define FLAG_L (1<<22)
const FLAG_L: i64 = 1 << 22;
// #define FLAG_H (1<<23)
const FLAG_H: i64 = 1 << 23;
// #define FLAG_F (1<<24)
const FLAG_F: i64 = 1 << 24;
// #define FLAG_C (1<<25)
const FLAG_C: i64 = 1 << 25;
// #define FLAG_A (1<<26)
const FLAG_A: i64 = 1 << 26;
// #define FLAG_o (1<<27)
const FLAG_o: i64 = 1 << 27;
// #define FLAG_g (1<<28)
const FLAG_g: i64 = 1 << 28;
// #define FLAG_Z (1<<29)
const FLAG_Z: i64 = 1 << 29;
// #define FLAG_show_control_chars (1<<30)
const FLAG_show_control_chars: i64 = 1 << 30;
// #define FLAG_full_time (1LL<<31)
const FLAG_full_time: i64 = 1 << 31;
// #define FLAG_color (1LL<<32)
const FLAG_color: i64 = 1 << 32;
// #endif
//

struct TT {
    /// For long display mode
    // w: i64,
    l: i64,
    color: Option<String>,
    files: MapTree<DirNode>,
    // singledir isn't really needed; we can just check if the root of the tree has only
    // one child.
    singledir: Option<TreeIdx>,
    screen_width: u32,
    // nl_title: i32,
    escmore: Option<&'static str>,
}

impl TT {
    fn new() -> Self {
        TT {
            l: 0,
            color: None,
            files: Default::default(),
            singledir: None,
            screen_width: 0,
            escmore: None,
        }
    }
}

impl Default for TT {
    fn default() -> Self {
        TT::new()
    }
}

#[derive(Clone, Debug)]
struct DirNode {
    metadata: Option<Metadata>,
    path: PathBuf,
    mtime_to_use: i64,
    st_blocks_to_use: u64,
    /// Place for user to store their stuff (can be pointer). This is used in ls to display LSM
    /// context (e.g. SELinux labelling). Use Fedora or CentOS to test this, as they have good
    /// support for SELinux.
    extra: String,
}

impl DirNode {
    fn new() -> Self {
        let cwd = std::env::current_dir().unwrap();
        let metadata = cwd.metadata().unwrap();
        DirNode {
            metadata: Some(metadata.clone()),
            path: cwd,
            mtime_to_use: metadata.st_mtime(),
            st_blocks_to_use: metadata.blksize(),
            extra: String::new(),
        }
    }

    fn get_file_name(&self) -> PathBuf {
        PathBuf::from(self.path.components().next_back().unwrap().as_os_str())
    }
}

impl Default for DirNode {
    fn default() -> Self {
        Self::new()
    }
}

fn create_node(
    path_to_add: &Path,
    follow_symlinks: bool,
    keep_failed_metadata: bool,
) -> Result<DirNode, std::io::Error> {
    let metadata = if follow_symlinks {
        let first_try = path_to_add.metadata();
        match first_try {
            Err(_) => {
                // If we got ENOENT without NOFOLLOW, try again with NOFOLLOW.
                if errno() != libc::ENOENT || follow_symlinks {
                    path_to_add.symlink_metadata()
                } else {
                    first_try
                }
            }
            _ => first_try,
        }
    } else {
        path_to_add.symlink_metadata()
    };

    match metadata {
        Ok(metadata) => Ok(DirNode {
            metadata: Some(metadata.clone()),
            path: path_to_add.to_path_buf(),
            mtime_to_use: metadata.st_mtime(),
            st_blocks_to_use: metadata.blksize(),
            extra: String::new(),
        }),
        Err(err) => {
            if keep_failed_metadata {
                Ok(DirNode {
                    metadata: None,
                    path: path_to_add.to_path_buf(),
                    mtime_to_use: 0,
                    st_blocks_to_use: 0,
                    extra: String::new(),
                })
            } else {
                Err(err)
            }
        }
    }
}

type CallbackFlag = i32;

fn isdotdot(path: &Path) -> bool {
    path.eq(&PathBuf::from(".")) || path.eq(&PathBuf::from(".."))
}

/// Return path to this node.
fn dirtree_path(tree: &MapTree<DirNode>, node_idx: TreeIdx) -> PathBuf {
    let node = tree.get(&node_idx).unwrap();
    match node.parent() {
        Some(_) => {
            let mut path = PathBuf::new();
            let mut nn_option: Option<&Node<DirNode>> = Some(node);
            while let Some(nn) = nn_option {
                if nn.parent().is_none() {
                    break;
                }
                path = {
                    let nn_path = if nn.parent().map_or(false, |parent| parent.is_root()) {
                        nn.value().path.clone()
                    } else {
                        nn.value().get_file_name()
                    };
                    if path.is_empty() {
                        nn_path
                    } else {
                        nn_path.join(path)
                    }
                };
                nn_option = nn.parent().as_ref().and_then(|parent| tree.get(parent));
            }

            path
        }
        _ => node.value().get_file_name(),
    }
}

/// Default callback, filters out "." and ".." except at top level.
fn dirtree_notdotdot(catch: &DirNode, has_parent: bool) -> CallbackFlag {
    if !has_parent || !isdotdot(&catch.path) {
        DIRTREE_SAVE | DIRTREE_RECURSE
    } else {
        0
    }
}

/// Toybox uses the `readdir` system call, which includes "." and ".."; however, Rust's
/// std `read_dir` does not include them.
static LINUX_READDIR_EXTRA_BEGINNING: [&str; 2] = [".", ".."];

/// Recursively read/process children of directory node, filtering through callback().
/// This will read the directory contents, reading/saving contents to display later in `tree`,
/// except for in "ls -1f" mode.
///
/// `DIRTREE_COMEAGAIN` (call again after handling all children of this directory) and
/// `DIRTREE_PROC` (skip non-numeric entries) are not implemented, because they're not used in ls.
///
/// # Arguments
///
/// * `dont_warn_metadata_fails` - Equivalent to `DIRTREE_SHUTUP`:  Don't warn about failure to get
///   metadata
/// * `follow_symlinks` - Follow symlinks to directories
/// * `keep_failed_metadata` - Equivalent to `DIRTREE_STATLESS`: Return files we can't get metadata
///   of
fn dirtree_recurse(
    tree: &mut MapTree<DirNode>,
    flag: &Flag,
    parent_idx: TreeIdx,
    dont_warn_metadata_fails: bool,
    follow_symlinks: bool,
    keep_failed_metadata: bool,
) {
    let (node, has_parent) = {
        // We assume that if we have a tree index, it must be an actual value in the tree.
        // We only have one map, and `TreeIdx` struct fields are private and only created by the
        // map_tree module.
        let tree_node = tree.get(&parent_idx).unwrap();
        (tree_node.value(), tree_node.parent().is_some())
    };

    let dir_iter = {
        let rust_dir = match fs::read_dir(&node.path) {
            Ok(dir) => dir,
            Err(e) => {
                if !dont_warn_metadata_fails {
                    eprintln_nonklee!(
                        "ls: {}: {}",
                        dirtree_path(tree, parent_idx).to_string_lossy(),
                        e
                    )
                }
                return;
            }
        };

        // `read_dir` alone doesn't include "." and ".."
        LINUX_READDIR_EXTRA_BEGINNING
            .iter()
            .map(PathBuf::from)
            .chain(
                rust_dir
                    .filter(|entry| entry.is_ok())
                    .map(|entry| entry.unwrap().path()),
            )
    };

    for entry in dir_iter {
        // Note: ls does not use DIRTREE_PROC, so this line of code from Toybox is left out:
        //
        //     if ((flags&DIRTREE_PROC) && !isdigit(*entry->d_name)) continue;
        //
        match create_node(&entry, follow_symlinks, keep_failed_metadata) {
            Ok(new_node) => {
                // From inode(7):
                // POSIX refers to the stat.st_mode bits corresponding to the mask S_IFMT
                // (see below) as the file type, the 12 bits  corresponding to the mask
                // 07777 as the file mode bits and the least significant 9 bits (0777) as
                // the file permission bits.
                // Modifies the node
                match dirtree_handle_callback(flag, new_node, has_parent) {
                    CallbackResult::Node(node) => tree.add(node, &parent_idx),
                    CallbackResult::Null => continue,
                    CallbackResult::Abort => break,
                }
            }
            Err(_) => continue,
        };
    }

    // Note: ls does not use DIRTREE_COMEAGAIN or DIRTREE_RECURSE
    // Original Toybox code not implemented:
    /*
    if (flags & DIRTREE_COMEAGAIN) {
      node->again |= 1;
      flags = callback(node);
    }
     */
}

enum CallbackResult {
    Node(DirNode),
    Null,
    Abort,
}

/// Handle callback for a node in the tree. Returns saved node(s) if
/// callback returns DIRTREE_SAVE, otherwise frees consumed nodes and
/// returns NULL.
fn dirtree_handle_callback(flag: &Flag, mut new: DirNode, has_parent: bool) -> CallbackResult {
    let flags = filter(flag, &mut new, has_parent);

    // ls does not use DIRTREE_RECURSE or DIRTREE_COMEAGAIN, so we're ignoring the extra
    // dirtree_recurse here. Original Toybox code not implemented:
    /*
    if (S_ISDIR(new->st.st_mode) && (flags & (DIRTREE_RECURSE|DIRTREE_COMEAGAIN))) {
      perror_msg("dirtree_handle_callback: INSIDE");
      flags = dirtree_recurse(new, callback, !*new->name ? AT_FDCWD :
                                             openat(dirtree_parentfd(new), new->name, O_CLOEXEC), flags);
    }
     */

    if (flags & DIRTREE_ABORT) == DIRTREE_ABORT {
        CallbackResult::Abort
    } else if flags & DIRTREE_SAVE == 0 {
        CallbackResult::Null
    } else {
        CallbackResult::Node(new)
    }
}

fn endtype(flag: &Flag, metadata: Option<&Metadata>) -> Option<char> {
    let metadata = metadata?;
    let mode = metadata.st_mode();
    if flag.F_append || flag.p_slash_dir_name && metadata.is_dir() {
        return Some('/');
    }
    if flag.F_append {
        if metadata.file_type().is_symlink() {
            return Some('@');
        }
        // is_file uses S_IFREG
        if metadata.is_file() && (mode & 0o111 != 0) {
            return Some('*');
        }
        if metadata.file_type().is_fifo() {
            return Some('|');
        }
        if metadata.file_type().is_socket() {
            return Some('=');
        }
    }
    None
}

fn numlen(int: u64) -> u32 {
    let mut digits = 0;
    let mut int = int;
    while int > 0 {
        int /= 10;
        digits += 1
    }
    digits
}

fn print_with_h(flag: &Flag, value: u64, units: u64) -> String {
    if flag.h_human_readable_sizes {
        human_readable(value * units, &HumanReadableStyle::default())
    } else {
        value.to_string()
    }
}

fn entrylen(flag: &Flag, dt: &DirNode, len: &mut Vec<usize>) {
    len[0] = dt.get_file_name().len();
    if endtype(flag, Option::from(&dt.metadata)).is_some() {
        len[0] += 1;
    }
    match &dt.metadata {
        None => {}
        Some(st) => {
            if flag.m_comma_separated {
                len[0] += 1;
            }
            len[1] = if flag.i_inode { numlen(st.st_ino()) } else { 0 } as usize;

            if flag.l_long
                || flag.o_long_no_group
                || flag.n_long_numeric_ids
                || flag.g_long_no_owner
            {
                len[2] = numlen(st.st_nlink()) as usize;
                len[3] = if flag.n_long_numeric_ids {
                    numlen(st.st_uid() as u64) as usize
                } else {
                    getusername(st.st_uid()).len()
                };
                len[4] = if flag.n_long_numeric_ids {
                    numlen(st.st_gid() as u64) as usize
                } else {
                    getgroupname(st.st_gid()).len()
                };
                len[5] = if st.file_type().is_block_device() || st.file_type().is_char_device() {
                    numlen(dev_major(st.st_rdev() as u32) as u64) as usize
                } else {
                    print_with_h(flag, st.st_size(), 1).len()
                }
            }

            len[6] = if flag.s_storage_used {
                print_with_h(flag, dt.st_blocks_to_use, 1024).len()
            } else {
                0
            } as usize;

            len[7] = if flag.Z_security_ctx {
                dt.extra.len()
            } else {
                0
            } as usize;
        }
    };
}

/// callback from dirtree_recurse() determining how to handle this entry.
fn filter(flag: &Flag, new: &mut DirNode, has_parent: bool) -> CallbackFlag {
    // Special case to handle enormous dirs without running out of memory.
    if flag.optflags == (FLAG_1 | FLAG_f) {
        println_nonklee!("{}", new.get_file_name().to_string_lossy());
        return 0;
    }

    if flag.Z_security_ctx {
        new.extra = if cfg!(feature = "selinux") {
            let ctx_str = if flag.L_follow_symlinks {
                lsm_get_context(&new.path)
            } else {
                lsm_lget_context(&new.path)
            };
            if let Some(ctx_str) = ctx_str {
                ctx_str
            } else {
                String::from("?")
            }
        } else {
            String::from("?")
        }
    }

    match &new.metadata {
        Some(metadata) => {
            new.mtime_to_use = if flag.c_ctime {
                metadata.st_ctime()
            } else if flag.u_access_time {
                metadata.st_atime()
            } else {
                metadata.st_mtime()
            };

            // Use 1KiB blocks rather than 512B blocks.
            new.st_blocks_to_use = metadata.st_blocks() >> 1;
        }
        None => {}
    };

    if flag.a_all || flag.full_time {
        return DIRTREE_SAVE;
    }
    // extremely complicated way of saying (!FLAG(A) && new->name[0]=='.')
    // Rust's `file_name` function doesn't work well on paths that terminate in ".."
    if !flag.A_list_all
        && new
            .path
            .components()
            .next_back()
            .map(|component| component.as_os_str())
            .unwrap_or_else(|| new.path.as_os_str())
            .as_bytes()
            .starts_with(".".as_bytes())
    {
        return 0;
    }

    // Since we're bitmasking to only use DIRTREE_SAVE, the ls program does not use DIRTREE_RECURSE.
    dirtree_notdotdot(new, has_parent) & DIRTREE_SAVE
}

fn next_column(flag: &Flag, ul: usize, dtlen: usize, columns: usize, xpos: &mut usize) -> usize {
    let mut ul = ul;
    let mut columns = columns;

    // Horizontal sort is easy
    if !flag.C_columns_vert_sort {
        *xpos = ul % columns;
        return ul;
    }

    // vertical sort (-x), uneven rounding goes along right edge
    let height = (dtlen + columns - 1) / columns; // round up
    let mut extra = dtlen % height; // how many rows are wider?
    if extra != 0 && ul >= extra * columns {
        ul -= extra * columns;
        columns -= 1
    } else {
        extra = 0;
    }

    *xpos = ul % columns;
    *xpos * height + extra + ul / columns
}

fn color_from_mode(mode: libc::mode_t) -> u32 {
    if S_ISDIR(mode) {
        256 + 34
    } else if S_ISLNK(mode) {
        256 + 36
    } else if S_ISBLK(mode) || S_ISCHR(mode) {
        256 + 33
    } else if S_ISREG(mode) && (mode & 0o111) != 0 {
        256 + 32
    } else if S_ISFIFO(mode) {
        33
    } else if S_ISSOCK(mode) {
        256 + 35
    } else {
        0
    }
}

fn zprint(zap: bool, pat: &str, len: i64, arg: &dyn Display) {
    let display = if zap {
        String::from("?")
    } else {
        arg.to_string()
    };
    if zap
        || pat
            .chars()
            .last()
            .map_or(false, |last_char| last_char == ' ')
    {
        if len >= 0 {
            print_nonklee!("{:>pad_width$} ", display, pad_width = len as usize)
        } else {
            print_nonklee!("{:<pad_width$} ", display, pad_width = len.abs() as usize)
        }
    } else if len >= 0 {
        print_nonklee!("{:>pad_width$}", display, pad_width = len as usize)
    } else {
        print_nonklee!("{:<pad_width$}", display, pad_width = len.abs() as usize)
    };
}

/// Recursively lists files in the directory mapped by the `indir_idx` to the `DirNode` in the
/// `TT.files` tree
fn listfiles(TT: &mut TT, flag: &mut Flag, indir_idx: TreeIdx, new_line_title_count: u64) {
    {
        // This should not fail, because TreeIdx creation is private and must come from the map.
        let indir = TT.files.get(&indir_idx).unwrap();

        if let Err(err) = std::fs::File::open(&indir.value().path) {
            eprintln_nonklee!("ls: {}: {}", indir.value().path.to_string_lossy(), err);
            return;
        }

        // Top level directory was already populated by main()
        if indir.parent().is_none() {
            // Silently descend into single directory listed by itself on command line.
            // In this case only show dirname/total header when given -R.
            let dt: Option<&Node<DirNode>> = {
                indir
                    .children()
                    .first()
                    .and_then(|first_child_idx| TT.files.get(first_child_idx))
            };
            if let Some(dt) = dt {
                let idx = dt.idx();
                let isdir = dt
                    .value()
                    .metadata
                    .as_ref()
                    .map_or(false, |metadata| metadata.is_dir());
                if isdir && indir.children().len() == 1 && !(flag.d_directory || flag.R_recursive) {
                    TT.singledir = Some(idx);
                    listfiles(TT, flag, idx, new_line_title_count);

                    return;
                }
            }

            // Do preprocessing (Dirtree didn't populate, so callback wasn't called.)
            let children = TT.files.get(&indir_idx).unwrap().children().to_owned();
            children.iter().for_each(|idx| {
                let child = TT.files.get_mut(idx).unwrap();
                filter(flag, child.value_mut(), false);
            });

            if flag.optflags == (FLAG_1 | FLAG_f) {
                // Note: `filter_new` already prints out the directory contents already as a
                // "special case to handle enormous dirs without running out of memory".
                return;
            }
        } else {
            // Read directory contents. We dup() the fd because this will close it.
            // This reads/saves contents to display later, except for in "ls -1f" mode.
            //
            // Note: The original flags translate to DIRTREE_STATLESS|DIRTREE_SYMFOLLOW*!!FLAG(L).
            // - FLAG(L) is a long integer,
            // - !! is double negation, so !!FLAG(L) == 0 if FLAG(L) == 0, and !!FLAG(L) == 1
            //   otherwise.
            // - In C, the order of operations dictates that logical NOT (!) comes before
            //   multiplication (*), which comes before bitwise OR (|), so DIRTREE_SYMFOLLOW is set
            //   iff the -L flag is used.
            dirtree_recurse(
                &mut TT.files,
                flag,
                indir_idx,
                false,
                flag.L_follow_symlinks,
                true,
            )
        }
    }

    let has_parent: bool;
    // This will contain the sorted directory entry indices for the TT.files tree.
    // Using TreeIdx means we minimize the amount of memory that will be copied and left when we
    // do recursion.
    let sorted_idx: Vec<TreeIdx>;
    let mut updated_new_line_title_count = new_line_title_count;
    // Add a block here so that any unused variables get dropped before we potentially recursively
    // list files.
    {
        let indir = TT.files.get(&indir_idx).unwrap();
        has_parent = indir.parent().is_some();

        // Copy linked list to array and sort it later. Directories go in array because
        // we visit them in sorted order too. (The nested loops let us measure and
        // fill with the same inner loop.)
        let mut sort: Vec<&Node<DirNode>> = indir
            .children()
            .iter()
            .map(|idx| TT.files.get(idx).unwrap())
            .collect();

        // Label directory if not top of tree, or if -R
        if indir.parent().is_some()
            && (TT
                .singledir
                .map_or(true, |single_dir_idx| single_dir_idx != indir.idx())
                || flag.R_recursive)
        {
            let path = dirtree_path(&TT.files, indir_idx);
            if updated_new_line_title_count != 0 {
                println_nonklee!()
            }
            updated_new_line_title_count += 1;
            println_nonklee!("{}:", path.to_string_lossy());
        }

        let mut totals: Vec<usize> = vec![0; 8];
        // Measure each entry to work out whitespace padding and total blocks
        let mut totpad: usize = 0;
        let mut len: Vec<usize> = vec![0; 8];
        if !flag.f_unsorted {
            sort.sort_by(|node_a, node_b| {
                let mut ret = Ordering::Equal;
                let metadata_a = &node_a.value().metadata;
                let metadata_b = &node_b.value().metadata;

                if flag.S_size {
                    let size_a = metadata_a.as_ref().map_or(0, |metadata| metadata.st_size());
                    let size_b = metadata_b.as_ref().map_or(0, |metadata| metadata.st_size());
                    ret = size_a.cmp(&size_b).reverse();
                }

                if flag.t_timestamp {
                    let mtime_a = node_a.value().mtime_to_use;
                    let mtime_b = node_b.value().mtime_to_use;
                    let mtime_tv_nsec_a = metadata_a
                        .as_ref()
                        .map_or(0, |metadata| metadata.st_mtime_nsec());
                    let mtime_tv_nsec_b = metadata_b
                        .as_ref()
                        .map_or(0, |metadata| metadata.st_mtime_nsec());

                    ret = if mtime_a > mtime_b {
                        Ordering::Less
                    } else if mtime_a < mtime_b {
                        Ordering::Greater
                    } else if mtime_tv_nsec_a > mtime_tv_nsec_b {
                        Ordering::Less
                    } else if mtime_tv_nsec_a < mtime_tv_nsec_b {
                        Ordering::Greater
                    } else {
                        ret
                    }
                }

                if ret == Ordering::Equal {
                    ret = node_a
                        .value()
                        .get_file_name()
                        .cmp(&node_b.value().get_file_name())
                }

                if flag.r_reverse {
                    ret.reverse()
                } else {
                    ret
                }
            });

            let mut blocks = 0u64;
            for entry in &sort {
                entrylen(flag, entry.value(), &mut len);
                for width in 1..totals.len() {
                    if len[width] > totals[width] {
                        totals[width] = len[width];
                    }
                }
                blocks += entry.value().st_blocks_to_use
            }

            totpad = totals[1] + !!totals[1] + totals[6] + !!totals[6] + totals[7] + !!totals[7];
            if (flag.h_human_readable_sizes
                || flag.l_long
                || flag.o_long_no_group
                || flag.n_long_numeric_ids
                || flag.g_long_no_owner
                || flag.s_storage_used)
                && indir.parent().is_some()
            {
                let tmp = print_with_h(flag, blocks, 1024);
                println_nonklee!("total {}", tmp);
            }
        }

        // The initial value for columns is sizeof(toybuf)/4, which is is 1024, because toybuf is
        // char[4096]
        let mut columns: usize = 1024;

        // Find largest entry in each field for display alignment
        let mut colsizes = vec![0; 4096];
        if flag.C_columns_vert_sort || flag.x_columns_horiz_sort {
            // columns can't be more than toybuf can hold, or more than files,
            // or > 1/2 screen width (one char filename, one space).
            if columns > (TT.screen_width / 2) as usize {
                columns = (TT.screen_width / 2) as usize;
            }
            if columns > sort.len() {
                columns = sort.len();
            }

            // Try to fit as many columns as we can, dropping down by one each time
            while columns > 1 {
                let mut totlen = columns;
                // Emulate memset to 0
                colsizes.iter_mut().take(columns).for_each(|elem| *elem = 0);

                let mut ul: usize = 0;
                while ul < sort.len() {
                    let mut c: usize = 0;
                    let cc = next_column(flag, ul, sort.len(), columns, &mut c);
                    if cc >= sort.len() {
                        // tilt: remainder bigger than height
                        break;
                    }
                    entrylen(flag, sort[cc].value(), &mut len);
                    if c < columns - 1 {
                        len[0] += totpad + 2; // 2 spaces between filenames
                    }
                    // Expand this column if necessary, break if that puts us over budget
                    if len[0] > colsizes[c] {
                        totlen += len[0] - colsizes[c];
                        colsizes[c] = len[0];
                        if totlen > TT.screen_width as usize {
                            break;
                        }
                    }

                    ul += 1
                }
                // If everything fit, stop here
                if ul == sort.len() {
                    break;
                }

                columns -= 1;
            }
        }

        // Loop through again to produce output.
        let mut width = 0;
        for ul in 0..sort.len() {
            let lastlen = len[0];
            let mut curcol: usize = 0;
            let dt = sort[next_column(flag, ul, sort.len(), columns, &mut curcol)];

            let stat = dt.value().metadata.as_ref();
            let mode = stat.map_or(0, |st| st.mode());
            let endtype = endtype(flag, stat);

            // If we couldn't stat, output ? for most fields
            let zap = stat.is_none()
                || stat.map_or(false, |st| {
                    st.st_blksize() == 0 || st.st_dev() == 0 || st.st_ino() == 0
                });

            // Skip directories at the top of the tree when -d isn't set
            if stat.map_or(false, |st| st.is_dir()) && indir.parent().is_none() && !flag.d_directory
            {
                continue;
            }
            updated_new_line_title_count = 1;

            // Handle padding and wrapping for display purposes
            entrylen(flag, dt.value(), &mut len);
            if ul != 0 {
                let mm_comma_sep = flag.m_comma_separated;
                if mm_comma_sep {
                    print_nonklee!(",")
                }
                if flag.C_columns_vert_sort || flag.x_columns_horiz_sort {
                    if curcol == 0 {
                        println_nonklee!();
                    } else {
                        if ul != 0 {
                            next_column(flag, ul - 1, sort.len(), columns, &mut curcol);
                        }
                        print_nonklee!(
                            "{:>pad_width$}",
                            ' ',
                            pad_width =
                                colsizes[if ul != 0 { curcol } else { 0 }] - lastlen - totpad
                        )
                    }
                } else if flag.one_file_per_line || width + 1 + len[0] > TT.screen_width as usize {
                    println_nonklee!();
                    width = 0;
                } else {
                    if mm_comma_sep {
                        print_nonklee!(" ");
                    } else {
                        print_nonklee!("  ");
                    }
                    width += 2 - if mm_comma_sep { 1 } else { 0 };
                }
            }
            width += len[0];

            if flag.i_inode {
                zprint(
                    zap,
                    "lu ",
                    totals[1] as i64,
                    &stat.map_or(0, |st| st.st_ino()),
                );
            }

            if flag.s_storage_used {
                let tmp = print_with_h(flag, dt.value().st_blocks_to_use, 1024);
                zprint(zap, "s ", totals[6] as i64, &tmp);
            }

            if flag.l_long
                || flag.o_long_no_group
                || flag.n_long_numeric_ids
                || flag.g_long_no_owner
            {
                let mode_str: String = {
                    let tmp = mode_to_string(mode);
                    if zap {
                        let mut zapped = String::from("?????????");
                        zapped.insert(0, tmp.chars().next().unwrap());
                        zapped
                    } else {
                        tmp
                    }
                };
                // Mode string is always of a fixed width; we don't need to use zprint.
                print_nonklee!("{}", mode_str);
                zprint(
                    zap,
                    "ld",
                    (totals[2] + 1) as i64,
                    &stat.map_or(0, |st| st.nlink()),
                );

                // print user
                if !flag.g_long_no_owner {
                    print_nonklee!(" ");
                    let ii = -(totals[3] as i64);
                    if zap || flag.n_long_numeric_ids {
                        zprint(zap, "lu", ii, &stat.map_or(0, |st| st.uid()));
                    } else {
                        let username = getusername(stat.map_or(0, |st| st.uid()));
                        // TODO: Implement draw_trim_esc
                        if let Some(str) = username.to_str() {
                            zprint(zap, "s", ii, &str);
                        } else {
                            zprint(zap, "lu", ii, &stat.map_or(0, |st| st.uid()));
                        }
                        //zprint(zap, "s", -ii, &username);
                    }
                }

                // print group
                if !flag.o_long_no_group {
                    print_nonklee!(" ");
                    let ii = -(totals[4] as i64);
                    if zap || flag.n_long_numeric_ids {
                        zprint(zap, "lu", ii, &stat.map_or(0, |st| st.gid()));
                    } else {
                        let groupname = getgroupname(stat.map_or(0, |st| st.gid()));
                        // TODO: Implement draw_trim_esc
                        if let Some(str) = groupname.to_str() {
                            zprint(zap, "s", ii, &str);
                        } else {
                            zprint(zap, "lu", ii, &stat.map_or(0, |st| st.gid()));
                        }
                        //zprint(zap, "s", -ii, &username);
                    }
                }
            }

            if flag.Z_security_ctx {
                // Toybox does the weird
                //     " %-*s "+!FLAG(l)
                // thing which just truncates the first character if !FLAG(l) == 1
                if flag.l_long {
                    print_nonklee!(" {:<pad_width$} ", dt.value().extra, pad_width = totals[7]);
                } else {
                    print_nonklee!("{:<pad_width$} ", dt.value().extra, pad_width = totals[7]);
                }
            }

            if flag.l_long
                || flag.o_long_no_group
                || flag.n_long_numeric_ids
                || flag.g_long_no_owner
            {
                // print major/minor, or size
                if !zap
                    && stat.map_or(false, |st| {
                        st.file_type().is_char_device() || st.file_type().is_block_device()
                    })
                {
                    let major = dev_major(stat.map_or(0, |st| st.rdev() as u32));
                    let minor = dev_minor(stat.map_or(0, |st| st.rdev() as u32));
                    print_nonklee!(
                        "{:<major_pad_width$}, {:<4}",
                        major,
                        minor,
                        major_pad_width = totals[5] - 4
                    );
                } else {
                    let tmp = print_with_h(flag, stat.map_or(0, |st| st.size()), 1);
                    zprint(zap, "s", (totals[5] + 1) as i64, &tmp);
                }

                // print time, always in --time-style=long-iso
                let time = Local.timestamp(dt.value().mtime_to_use, 0);
                let mut time_str = time.format(" %F %H:%M").to_string();

                let len = if flag.full_time {
                    time_str.push_str(&*format!(
                        ":{:02}.{:09} ",
                        time.second(),
                        stat.map_or(0, |st| st.mtime_nsec())
                    ));
                    time_str.push_str(&time.format("%z").to_string());
                    17 + 13
                } else {
                    17
                };

                zprint(zap, "s ", len, &time_str);
            }

            if flag.color.is_some() {
                let mode = stat.map_or(0, |st| st.mode());
                let color = color_from_mode(mode);

                if color != 0 {
                    // hex escapes because Rust doesn't support octal ones
                    print_nonklee!("\x1b[{};{}m", color >> 8, color & 255);
                }
            }

            // TODO: crunch_str
            print_nonklee!("{}", dt.value().get_file_name().to_string_lossy());

            if flag.color.is_some() {
                print_nonklee!("\x1b[0m");
            }

            if (flag.l_long
                || flag.o_long_no_group
                || flag.n_long_numeric_ids
                || flag.g_long_no_owner)
                && stat.map_or(false, |st| st.file_type().is_symlink())
            {
                print_nonklee!(" -> ");
                if !zap && flag.color.is_some() {
                    let color = match fs::metadata(&dt.value().path) {
                        Ok(st2) => color_from_mode(st2.mode()),
                        Err(_) => 256 + 31,
                    };

                    if color != 0 {
                        print_nonklee!("\x1b[{};{}m", color >> 8, color & 255);
                    }
                }

                let link = if let Ok(link) = dt.value().path.read_link() {
                    link.to_string_lossy().to_string()
                } else {
                    String::from('?')
                };

                zprint(zap, "s", 0, &link);
                if !zap && flag.color.is_some() {
                    print_nonklee!("\x1b[0m");
                }
            }

            if let Some(et) = endtype {
                print_nonklee!("{}", et);
            }
        }

        if width != 0 {
            println_nonklee!();
        }

        // Although this is going to create a new vector, this is cheaper (memory-wise) than having
        // to create a new vector containing cloned Node<DirNode>s in order to be able to use this
        // outside of the block.
        sorted_idx = sort.iter().map(|entry| entry.idx()).collect();
    }

    // Possible recursion
    for entry_idx in sorted_idx {
        let should_recurse = {
            let entry = TT.files.get(&entry_idx).unwrap();
            if flag.d_directory
                || !entry
                    .value()
                    .metadata
                    .as_ref()
                    .map_or(false, |stat| stat.is_dir())
            {
                continue;
            }

            // Recurse into dirs if at top of the tree or given -R
            !has_parent || (flag.R_recursive && dirtree_notdotdot(entry.value(), has_parent) != 0)
        };

        if should_recurse {
            listfiles(TT, flag, entry_idx, updated_new_line_title_count);
        }
    }
}

#[cfg(feature = "verifier-klee")]
fn get_flags() -> Flag {
    for arg in args_os() {
        // path merges
        verifier::coherent! {{
            verifier::assume(arg.len() > 0 && arg.is_ascii());
            verifier::assume(arg.as_bytes().iter().all(|b| 33 <= *b && *b <= 136));
        }}
    }

    let flag: Flag = {
        let flagResult: Result<Flag, structopt::clap::Error> = Flag::from_args_safe();
        verifier::assume(flagResult.is_ok());
        flagResult.unwrap()
    };

    verifier::assume(flag.color.is_none());

    flag
}


#[cfg(not(feature = "verifier-klee"))]
fn get_flags() -> Flag {
    match Flag::from_args_safe() {
        Ok(flag) => {
            flag
        },
        Err(err) => {
            eprintln_nonklee!("{}", err.message);
            exit(2);
        }
    }
}

fn main() {
    let mut flag: Flag = get_flags();

    flag.optflags |= if flag.one_file_per_line { FLAG_1 } else { 0 }
        | if flag.x_columns_horiz_sort { FLAG_x } else { 0 }
        | if flag.w_column_width.is_some() {
            FLAG_w
        } else {
            0
        }
        | if flag.u_access_time { FLAG_u } else { 0 }
        | if flag.t_timestamp { FLAG_t } else { 0 }
        | if flag.s_storage_used { FLAG_s } else { 0 }
        | if flag.r_reverse { FLAG_r } else { 0 }
        | if flag.q_unprintable_chars { FLAG_q } else { 0 }
        | if flag.p_slash_dir_name { FLAG_p } else { 0 }
        | if flag.n_long_numeric_ids { FLAG_n } else { 0 }
        | if flag.m_comma_separated { FLAG_m } else { 0 }
        | if flag.l_long { FLAG_l } else { 0 }
        | if flag.k { FLAG_k } else { 0 }
        | if flag.i_inode { FLAG_i } else { 0 }
        | if flag.h_human_readable_sizes {
            FLAG_h
        } else {
            0
        }
        | if flag.f_unsorted { FLAG_f } else { 0 }
        | if flag.d_directory { FLAG_d } else { 0 }
        | if flag.c_ctime { FLAG_c } else { 0 }
        | if flag.b_escape_nongraphic_chars {
            FLAG_b
        } else {
            0
        }
        | if flag.a_all { FLAG_a } else { 0 }
        | if flag.S_size { FLAG_S } else { 0 }
        | if flag.R_recursive { FLAG_R } else { 0 }
        | if flag.L_follow_symlinks { FLAG_L } else { 0 }
        | if flag.H_follow_cli_symlinks {
            FLAG_H
        } else {
            0
        }
        | if flag.F_append { FLAG_F } else { 0 }
        | if flag.C_columns_vert_sort { FLAG_C } else { 0 }
        | if flag.A_list_all { FLAG_A } else { 0 }
        | if flag.o_long_no_group { FLAG_o } else { 0 }
        | if flag.g_long_no_owner { FLAG_g } else { 0 }
        | if flag.Z_security_ctx { FLAG_Z } else { 0 }
        | if flag.show_control_chars {
            FLAG_show_control_chars
        } else {
            0
        }
        | if flag.full_time { FLAG_full_time } else { 0 }
        | if flag.color.is_some() { FLAG_color } else { 0 };

    let mut TT = TT {
        l: if flag.l_long { 1 } else { 0 },
        color: flag.color.clone(),
        ..Default::default()
    };

    if flag.full_time {
        flag.l_long = true;
        TT.l = 2;
    }

    // Do we have an implied -1
    if nix::unistd::isatty(1).unwrap_or(false) {
        if !flag.show_control_chars {
            flag.b_escape_nongraphic_chars = true
        };
        if flag.l_long || flag.o_long_no_group || flag.n_long_numeric_ids || flag.g_long_no_owner {
            flag.one_file_per_line = true;
        } else if !(flag.one_file_per_line || flag.x_columns_horiz_sort || flag.m_comma_separated) {
            flag.C_columns_vert_sort = true;
        }
    } else {
        if !flag.n_long_numeric_ids {
            flag.one_file_per_line = true
        };
        if TT.color.is_some() {
            flag.optflags ^= FLAG_color;
        }
    }

    TT.screen_width = 80;
    if let Some(width) = flag.w_column_width {
        TT.screen_width = width + 2;
    } else {
        lib::tty::terminal_size(Some(&mut TT.screen_width), None);
    }
    if TT.screen_width < 2 {
        TT.screen_width = 2;
    }
    if flag.b_escape_nongraphic_chars {
        TT.escmore = Some(" \\");
    }

    // The optflags parsing infrastructure should really do this for us,
    // but currently it has "switch off when this is set", so "-dR" and "-Rd"
    // behave differently
    if flag.d_directory {
        flag.R_recursive = false;
    }

    // Iterate through command line arguments, collecting directories and files.
    // Non-absolute paths are relative to current directory. Top of tree is
    // a dummy node to collect command line arguments into pseudo-directory.
    let dummy_node = DirNode::default();
    TT.files.add(dummy_node, &TreeIdx::root_idx());

    let default_args = [PathBuf::from(".")];
    let iter = if !flag.args.is_empty() {
        flag.args.iter()
    } else {
        default_args.iter()
    };

    for path in iter {
        let sym = !(flag.l_long | flag.d_directory | flag.F_append)
            | flag.L_follow_symlinks
            | flag.H_follow_cli_symlinks;

        match create_node(path, sym, true) {
            Ok(node) => {
                // The dt->again&2 check is just checking if the stat call failed
                if node.metadata.is_none() {
                    // std adds "(os error {})" to the end of strings from strerror!
                    // https://github.com/rust-lang/rust/blob/4da89a180facdecf168cbe0ddbc6bfbdd9f6e696/library/std/src/io/error.rs#L724
                    if let Err(err) = fs::metadata(path) {
                        eprintln_nonklee!("ls: {}: {}", path.to_string_lossy(), err);
                    } else if let Err(err) = fs::symlink_metadata(path) {
                        eprintln_nonklee!("ls: {}: {}", path.to_string_lossy(), err);
                    } else {
                        eprintln_nonklee!("ls: {}: Failed to get metadata", path.to_string_lossy());
                    }
                } else {
                    TT.files.add(node, &TreeIdx::root_idx());
                }
            }
            Err(_) => {
                panic!("unexpected");
            }
        }
    }

    listfiles(&mut TT, &mut flag, TreeIdx::root_idx(), 0);
}
