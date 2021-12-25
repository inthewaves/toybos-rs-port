#![feature(osstring_ascii)]
#![allow(non_snake_case)]

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::env::{args, args_os};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{stdin, BufRead, BufReader, Read, StdinLock};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::os::unix::prelude::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::{fs, io, mem};

use nix::unistd::{lseek, Whence};
use nix::NixPath;
use rand::{RngCore, SeedableRng};
use rand_pcg::Pcg32;
use structopt::StructOpt;

use crate::lib::lib::regexec0;
use crate::lib::xwrap::{xputl, xputl_bytes, xregcomp};
use crate::utils::bufreader_delim::SplitWithDelim;
use crate::utils::string_util::{strcasestr, strstr};

#[cfg(feature = "verifier-klee")]
use verification_annotations::prelude::*;

mod lib;
mod utils;

#[cfg(feature = "verifier-klee")]
const MAX_SYMBOLIC_FILE_SIZE: usize = 6;

const ABOUT: &str = "Show lines matching regular expressions. If no -e, first argument is
regular expression to match. With no files (or \"-\" filename) read stdin.
Returns 0 if matched, 1 if no match found, 2 for command errors.";

#[derive(Debug, StructOpt, Default)]
#[structopt(name = "grep", about = ABOUT)]
struct Flag {
    #[structopt(long)]
    color: Option<String>,

    /// Regex to match. (May be repeated.)
    #[structopt(short, number_of_values = 1)]
    e_regex_to_match: Vec<OsString>,
    /// File listing regular expressions to match.
    #[structopt(short)]
    f_file_with_regex: Option<PathBuf>,

    // file search:
    /// Recurse into subdirectories (defaults FILE to ".")
    #[structopt(short)]
    r_recurse: bool,
    /// Recurse into subdirectories and symlinks to directories
    #[structopt(short = "R")]
    R_recurse_symlink: bool,
    /// Match filename pattern (--include)
    #[structopt(short = "M", long = "include", number_of_values = 1)]
    M_match_filename_pattern: Vec<OsString>,
    /// Skip filename pattern (--exclude)
    #[structopt(short = "S", long = "exclude", number_of_values = 1)]
    S_skip_filename_pattern: Vec<OsString>,
    /// Ignore binary files
    #[structopt(short = "I")]
    I_ignore_bin_files: bool,

    // match type:
    /// Show NUM lines after
    #[structopt(short = "A", default_value)]
    A_show_num_lines_after: i32,
    /// Show NUM lines before match
    #[structopt(short = "B", default_value)]
    B_show_num_lines_before: i32,
    /// NUM lines context (A+B)
    #[structopt(short = "C", default_value)]
    C_num_lines_context: i32,
    /// extended regex syntax
    #[structopt(short = "E")]
    E_extended_regex_syntax: bool,
    /// fixed (literal match)
    #[structopt(short = "F")]
    F_fixed: bool,
    /// always text (not binary)
    #[structopt(short)]
    a_always_text: bool,
    /// case insensitive
    #[structopt(short)]
    i_case_insens: bool,
    /// match MAX many lines
    #[structopt(short, default_value)]
    m_match_max_lines: i32,
    /// invert match
    #[structopt(short)]
    v_invert_match: bool,
    /// whole word (implies -E)
    #[structopt(short)]
    w_whole_wrd: bool,
    /// whole line
    #[structopt(short)]
    x_whole_line: bool,
    /// input NUL terminated
    #[structopt(short)]
    z_input_nul_terminated: bool,

    // display modes: (default: matched line)
    /// filenames with no match
    #[structopt(short = "L", long = "files-without-match")]
    L_filenames_with_no_match: bool,
    /// output is NUL terminated
    #[structopt(short = "Z")]
    Z_output_is_nul_terminated: bool,
    /// count of matching lines
    #[structopt(short)]
    c_count_of_matching_lines: bool,
    /// filenames with a match
    #[structopt(short, long = "files-with-matches")]
    l_filenames_with_a_match: bool,
    /// only matching part
    #[structopt(short, long = "only-matching")]
    o_only_matching_part: bool,
    /// quiet (errors only)
    #[structopt(short, long)]
    quiet: bool,
    /// silent (no error msg)
    #[structopt(short, long)]
    silent: bool,

    // output prefix (default: filename if checking more than 1 file):
    /// force filename
    #[structopt(short = "H")]
    H_force_filename: bool,
    /// byte offset of match
    #[structopt(short, long = "byte-offset")]
    b_byte_offset_of_match: bool,
    /// hide filename
    #[structopt(short, long = "no-filename")]
    h_hide_filename: bool,
    /// line number of match
    #[structopt(short)]
    n_line_number_of_match: bool,
    #[structopt(long = "exclude-dir", number_of_values = 1)]
    exclude_dir: Vec<PathBuf>,

    regex_or_files: Vec<OsString>,
}

#[cfg(feature = "verifier-klee")]
impl Flag {
    fn abstract_value() -> Self {
        let symbolic_args: Vec<OsString> = args_os().skip(1).collect();

        /*    let flag = Flag {
            color: None,
            e_regex_to_match: vec![],
            f_file_with_regex: None,
            r_recurse: bool::abstract_value(),
            R_recurse_symlink: bool::abstract_value(),
            M_match_filename_pattern: vec![],
            S_skip_filename_pattern: vec![],
            I_ignore_bin_files: bool::abstract_value(),
            A_show_num_lines_after: 0, // i32::abstract_value()
            B_show_num_lines_before: 0,
            C_num_lines_context: 0,
            E_extended_regex_syntax: true,
            F_fixed: bool::abstract_value(),
            a_always_text: bool::abstract_value(),
            i_case_insens: bool::abstract_value(),
            m_match_max_lines: 0,
            v_invert_match: bool::abstract_value(),
            w_whole_wrd: bool::abstract_value(),
            x_whole_line: bool::abstract_value(),
            z_input_nul_terminated: bool::abstract_value(),
            L_filenames_with_no_match: bool::abstract_value(),
            Z_output_is_nul_terminated: bool::abstract_value(),
            c_count_of_matching_lines: bool::abstract_value(),
            l_filenames_with_a_match: bool::abstract_value(),
            o_only_matching_part: bool::abstract_value(),
            quiet: bool::abstract_value(),
            silent: true,
            H_force_filename: bool::abstract_value(),
            b_byte_offset_of_match: bool::abstract_value(),
            h_hide_filename: bool::abstract_value(),
            n_line_number_of_match: bool::abstract_value(),
            exclude_dir: vec![],
            regex_or_files: symbolic_args
        };*/

        let flag = Flag {
            color: None,
            e_regex_to_match: vec![],
            f_file_with_regex: None,
            r_recurse: false,
            R_recurse_symlink: false,
            M_match_filename_pattern: vec![],
            S_skip_filename_pattern: vec![],
            I_ignore_bin_files: false,
            A_show_num_lines_after: 0,
            B_show_num_lines_before: 0,
            C_num_lines_context: 0,
            E_extended_regex_syntax: true,
            F_fixed: bool::abstract_value(),
            a_always_text: false,
            i_case_insens: bool::abstract_value(),
            m_match_max_lines: 0,
            v_invert_match: bool::abstract_value(),
            w_whole_wrd: bool::abstract_value(),
            x_whole_line: false,
            z_input_nul_terminated: false,
            L_filenames_with_no_match: false,
            Z_output_is_nul_terminated: false,
            c_count_of_matching_lines: false,
            l_filenames_with_a_match: false,
            o_only_matching_part: false,
            quiet: false,
            silent: true, // always assume true to prevent eprintln spam
            H_force_filename: false,
            b_byte_offset_of_match: false,
            h_hide_filename: false,
            n_line_number_of_match: false,
            exclude_dir: vec![],
            regex_or_files: symbolic_args,
        };

        verifier::assume(flag.silent);
        verifier::assume(0 <= flag.A_show_num_lines_after && flag.A_show_num_lines_after <= 100);
        verifier::assume(0 <= flag.B_show_num_lines_before && flag.B_show_num_lines_before <= 100);
        verifier::assume(0 <= flag.C_num_lines_context && flag.C_num_lines_context <= 100);
        verifier::assume(0 <= flag.m_match_max_lines && flag.m_match_max_lines <= 100);

        verifier::assume(!flag.R_recurse_symlink || flag.r_recurse);

        flag
    }
}

#[derive(Debug, Default)]
struct TT {
    purple: &'static str,
    cyan: &'static str,
    red: &'static str,
    green: &'static str,
    grey: &'static str,
    found: bool,
    indelim: char,
    outdelim: char,
    reg: Vec<Reg>,
    tried: u32,
}

#[derive(Debug)]
struct Reg {
    recheck: i32,
    regex: libc::regex_t,
    match_res: libc::regmatch_t,
}

impl Reg {
    fn new(regex: &OsStr, flags: i32) -> Reg {
        let mut regex_compiled: libc::regex_t = unsafe { mem::zeroed() };
        xregcomp(&mut regex_compiled, regex, flags);
        Reg {
            recheck: 0,
            regex: regex_compiled,
            match_res: libc::regmatch_t { rm_so: 0, rm_eo: 0 },
        }
    }

    fn match_str(&mut self, input: &OsStr, length: i64, eflags: i32) -> Result<(), ()> {
        if regexec0(&self.regex, input, length, 1, &mut self.match_res, eflags) == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Use `cargo-verify --clean -vvv --backend-flags='--use-merge,--max-time=60min,--external-calls=all' --bin grep --test test_reg`
/// to test. From https://klee.github.io/docs/options/, we have to use concrete values when calling
/// these external functions. Otherwise, we get an error that says
///
///     KLEE: ERROR: src/lib/xwrap.rs:39: external call with symbolic argument: regcomp
///     Error: external call with symbolic argument: regcomp
///
#[test]
#[cfg(feature = "verifier-klee")]
fn test_rand_num() {
    let mut rand = Pcg32::seed_from_u64(u64::abstract_value());
    // This test takes forever to run
    verifier_assert!(rand.next_u64() == 43);

    /*
    let max_len: i64 = 4096;

    let expression = verifier::verifier_nondet_ascii_string(max_len as usize);
    let flags = i32::abstract_value();
    let mut reg = Reg::new(OsStr::from_bytes(expression.as_bytes()), flags);

    let input = verifier::verifier_nondet_ascii_string(max_len as usize);
    let length = i64::abstract_where(|len| 0 <= *len && *len <= max_len);
    let eflags = i32::abstract_value();
    reg.match_str(OsStr::from_bytes(input.as_bytes()), length, eflags);

     */
}


impl Drop for Reg {
    fn drop(&mut self) {
        let regex: *mut libc::regex_t = &mut self.regex;
        unsafe { libc::regfree(regex) };
    }
}

fn parse_regex(flag: &mut Flag, TT: &mut TT) {
    // Note: from lib.h: struct arg_list - stores a pointer to a single string
    // char *arg which is stored in a separate chunk of memory.

    // Add all -f lines to -e list.
    if let Some(file_with_regex) = &flag.f_file_with_regex {
        // Toybox reads the entire contents of the regex file.
        match fs::read(file_with_regex) {
            Ok(file_bytes) if !file_bytes.is_empty() && !file_bytes.starts_with(&[0]) => {
                // Toybox inserts these at the front.
                flag.e_regex_to_match
                    .insert(0, OsString::from_vec(file_bytes))
            }
            _ => {}
        }
    }

    // Split lines at \n, add individual lines to new list.
    let mut split_regex_lines_list: Vec<OsString> = Vec::new();
    for expr in &flag.e_regex_to_match {
        let expr = expr.as_bytes();
        if expr.is_empty() {
            split_regex_lines_list.push(OsString::new());
            continue;
        }

        let cursor = io::Cursor::new(expr);
        // `split` is good and doesn't include an empty string at the end, like str's
        // `split_terminator`. It also gets rid of the \n characters at the end, which is what
        // Toybox does.
        for line in cursor.split(b'\n') {
            match line {
                Ok(line) => {
                    split_regex_lines_list.push(OsString::from_vec(line));
                }
                Err(e) => {
                    panic!(
                        "I/O errors shouldn't happen as we are reading from an in-memory string! \
                        Got error: {}",
                        e
                    )
                }
            }
        }
    }
    flag.e_regex_to_match = split_regex_lines_list;

    if !flag.F_fixed {
        let regex_flags = {
            let mut regex_flags = 0;
            if flag.E_extended_regex_syntax {
                regex_flags |= libc::REG_EXTENDED
            }
            if flag.i_case_insens {
                regex_flags |= libc::REG_ICASE
            }
            regex_flags
        };

        // Convert regex list
        for regex in &flag.e_regex_to_match {
            if flag.o_only_matching_part && regex.is_empty() {
                continue;
            }

            TT.reg.push(Reg::new(regex, regex_flags));
        }
    }
}

#[test]
#[cfg(feature = "verifier-klee")]
fn test_parse_regex() {
    let flags = Flag::default();

    let indelim = u8::abstract_value() as char;
    let outdelim = u8::abstract_value() as char;

    verifier::assume(indelim == '\n' || indelim == '\u{0}');
    verifier::assume(outdelim == '\n' || outdelim == '\u{0}');
    verifier::assume((indelim == '\n') == flags.z_input_nul_terminated);
    verifier::assume((outdelim == '\n') == flags.Z_output_is_nul_terminated);

    let TT = TT {
        purple: "",
        cyan: "",
        red: "",
        green: "",
        grey: "",
        found: false,
        indelim,
        outdelim,
        reg: vec![],
        tried: 0,
    };
}

enum FileType {
    Path(File),
    Stdin,
}

fn numdash(TT: &TT, num: usize, dash: char) {
    print_nonklee!("{}{}{}{}", TT.green, num, TT.cyan, dash);
}

/// Emit line with various potential prefixes and delimiter
#[allow(clippy::too_many_arguments)]
fn outline(
    flag: &Flag,
    TT: &TT,
    line: Option<&OsStr>,
    dash: char,
    name: &Path,
    lcount: usize,
    bcount: usize,
    trim: u32,
) {
    if cfg!(feature = "verifier-klee") {
        return;
    }

    if trim == 0 && flag.o_only_matching_part {
        return;
    }
    if !name.is_empty() && flag.H_force_filename {
        print_nonklee!("{}{}{}{}", TT.purple, name.to_string_lossy(), TT.cyan, dash);
    }
    if flag.c_count_of_matching_lines {
        print_nonklee!("{}{}", TT.grey, lcount);
        print_nonklee!("{}", TT.outdelim);
    } else if lcount != 0 && flag.n_line_number_of_match {
        numdash(TT, lcount, dash);
    }

    if bcount != 0 && flag.b_byte_offset_of_match {
        numdash(TT, bcount - 1, dash);
    }
    if let Some(line) = line {
        if flag.color.is_some() {
            print_nonklee!(
                "{}",
                if flag.o_only_matching_part {
                    TT.red
                } else {
                    TT.grey
                }
            );
        }
        // TODO: support embedded NUL bytes in output
        xputl(line, trim);
        print_nonklee!("{}", TT.outdelim);
    }
}

fn do_grep(flag: &mut Flag, TT: &mut TT, file_type: FileType, name: &Path) {
    if !flag.r_recurse {
        TT.tried += 1;
    }

    let name = match file_type {
        FileType::Path(_) => name.to_owned(),
        FileType::Stdin => PathBuf::from("(standard input)"),
    };

    // Only run binary file check on lseekable files.
    let bin = if cfg!(feature = "verifier-klee") {
        // Not very important for testing due to path explosion.
        //
        // This check isn't very robust anyway, since bytes past the first 256 of a file can be
        // non-UTF-8 bytes.
        //
        // The value of bin is only used to
        // - skip if the -I (ignore bin files) flag is used;
        // - print "Binary file matches" instead of grep print out if a file is determined to be
        //   binary; and
        // - skip the discarded line buffer popping if the -B (show # lines before) flag is used and
        //   the file is determined to be binary
        // None of these are particularly important for testing.
        false
    } else {
        let file = match &file_type {
            FileType::Path(file) => Some(file),
            FileType::Stdin => None,
        };

        // Use the raw fd for stdin
        if !flag.a_always_text
            && lseek(file.map_or(0, |file| file.as_raw_fd()), 0, Whence::SeekCur)
                .map_or(false, |offset| offset == 0)
        {

            // If the first 256 bytes don't parse as utf8, call it binary.
            let mut buf = vec![0u8; 256];
            let should_check = match file {
                Some(file) => file
                    .read_at(&mut buf, 0)
                    .map_or(false, |bytes_read| bytes_read > 0),
                None => io::stdin()
                    .read(&mut buf)
                    .map_or(false, |bytes_read| bytes_read > 0),
            };

            if should_check {
                core::str::from_utf8(&buf).is_err()
            } else {
                false
            }
        } else {
            false
        }
    };

    if bin && flag.I_ignore_bin_files {
        return;
    }

    // Loop through every line of input

    let mut matched = 0;
    let mut offset = 0;
    let mut lcount = 0;
    let mut bars: Option<&str> = None;

    #[derive(Debug)]
    struct DiscardedLine {
        str: OsString,
        bcount: usize,
        trim: u32,
    }

    let mut discarded_line_buffer: VecDeque<DiscardedLine> = VecDeque::new();
    let mut mcount = 0;
    let mut after = 0;
    // Before is not used, because it's basically keeping track of discarded_line_buffer's size
    // let mut before = 0;

    // Returns whether the outer function should also return
    let mut process_line = |flag: &mut Flag, TT: &mut TT, line: OsString, name: &Path| -> bool {
        lcount += 1;
        matched = 0;

        let len = line.as_bytes().len();

        let line = if line.as_bytes().ends_with(&[TT.indelim as u8]) {
            let mut line_without_delim = line.as_bytes().to_vec();
            line_without_delim.pop();
            OsString::from_vec(line_without_delim)
        } else {
            line
        };

        let ulen = line.as_bytes().len();

        TT.reg.iter_mut().for_each(|shoe| shoe.recheck = 0);

        // Loop to handle multiple matches in same line
        let mut start: usize = 0;
        let mut rc;

        // Toybox uses toybuf for this, which is some statically allocated memory space that's
        // persistent for the whole execution.
        let mut mm_buffer = libc::regmatch_t { rm_so: 0, rm_eo: 0 };
        // Mimic a do-while loop.
        let mut has_iterated = false;
        while !has_iterated || start < line.len() {
            has_iterated = true;
            let mut mm = &mut mm_buffer;

            if flag.F_fixed {
                let mut s: Option<usize> = None;
                let mut seek_len: Option<usize> = None;
                for seek in &flag.e_regex_to_match {
                    seek_len = Some(seek.len());
                    s = if flag.x_whole_line {
                        let check = if flag.i_case_insens {
                            let seek = seek.to_ascii_lowercase();
                            let line = line.to_ascii_lowercase();
                            seek.cmp(&line)
                        } else {
                            seek.cmp(&line)
                        };
                        if check == Ordering::Equal {
                            Some(0)
                        } else {
                            None
                        }
                    } else if seek.as_bytes().first().map_or(false, |arg| *arg == 0)
                        || seek.is_empty()
                    {
                        // If an empty string is among the expressions to match exactly, then match
                        // the entire line.
                        Some(0)
                    } else if flag.i_case_insens {
                        let start = &line.as_bytes()[start..];
                        strcasestr(start, seek.as_bytes())
                    } else {
                        let start = &line.as_bytes()[start..];
                        strstr(start, seek.as_bytes())
                    };

                    if s.is_some() {
                        break;
                    }
                }
                rc = if let (Some(s), Some(seek_len)) = (s, seek_len) {
                    mm.rm_so = s as i32;
                    mm.rm_eo = (s + seek_len) as i32;
                    0
                } else {
                    1
                };
            } else {
                // Handle regex matches
                let baseline = mm.rm_eo;
                mm.rm_eo = i32::MAX;
                mm.rm_so = mm.rm_eo;
                rc = 1;
                for shoe in &mut TT.reg {
                    // Do we need to re-check this regex?
                    if shoe.recheck == 0 {
                        shoe.match_res.rm_so -= baseline;
                        shoe.match_res.rm_eo -= baseline;
                        if matched == 0 || shoe.match_res.rm_so < 0 {
                            let str = OsString::from_vec((&line.as_bytes()[start..]).to_vec());
                            shoe.recheck = if shoe
                                .match_str(
                                    &str,
                                    (ulen - start) as i64,
                                    if start == 0 { 0 } else { libc::REG_NOTBOL },
                                )
                                .is_ok()
                            {
                                0
                            } else {
                                libc::REG_NOMATCH
                            };
                        }
                    }

                    // If we got a match, is it a _better_ match?
                    if shoe.recheck == 0
                        && (shoe.match_res.rm_so < mm.rm_so
                            || (shoe.match_res.rm_so == mm.rm_so
                                && shoe.match_res.rm_eo >= mm.rm_eo))
                    {
                        // Note: The Toybox code uses mm = &shoe->m;
                        mm.rm_so = shoe.match_res.rm_so;
                        mm.rm_eo = shoe.match_res.rm_eo;
                        rc = 0;
                    }
                }
            }

            if rc == 0 && flag.o_only_matching_part && mm.rm_eo == 0 && ulen > start {
                start += 1;
                continue;
            }

            if rc == 0 && flag.x_whole_line && (mm.rm_so != 0 || ulen - start != mm.rm_eo as usize)
            {
                rc = 1;
            }

            if rc == 0 && flag.w_whole_wrd {
                let mut c: char = 0 as char;
                let start_array = &line.as_bytes()[start..];
                let idx = start + (mm.rm_so as usize);
                if idx != 0 {
                    // Toybox does `start[mm->rm_so-1]`, which accesses the memory location
                    // immediately preceding `start` if mm->rm_so <= 0. `start` in Toybox's grep is
                    // a pointer to a location in the string `line`.
                    c = if mm.rm_so - 1 < 0 {
                        let idx = ((start as i32) + (mm.rm_so - 1)) as usize;
                        match line.as_bytes().get(idx) {
                            None => c,
                            Some(char) => *char as char,
                        }
                    } else {
                        match start_array.get((mm.rm_so - 1) as usize) {
                            None => c,
                            Some(char) => *char as char,
                        }
                    };

                    if !c.is_alphanumeric() && c != '_' {
                        c = 0 as char;
                    }
                }
                if c == 0 as char {
                    // If this is out of bounds, like mm.rm_eo == start_array.len(), Toybox will
                    // not segfault or crash. (e.g., if mm.rm_eo == start_array.len(), then c will
                    // take the nul byte at the end of the string. Weird semantics, but let's
                    // preserve them.
                    c = match start_array.get((mm.rm_eo) as usize) {
                        None => c,
                        Some(char) => *char as char,
                    };

                    if !c.is_alphanumeric() && c != '_' {
                        c = 0 as char;
                    }
                }
                if c != 0 as char {
                    start += (mm.rm_so + 1) as usize;
                    continue;
                }
            }

            if flag.v_invert_match {
                if flag.o_only_matching_part {
                    if rc != 0 {
                        mm.rm_eo = (ulen - start) as i32;
                    } else if mm.rm_so == 0 {
                        start += mm.rm_eo as usize;
                        continue;
                    } else {
                        mm.rm_eo = mm.rm_so;
                    }
                } else {
                    if rc == 0 {
                        break;
                    }
                    mm.rm_eo = (ulen - start) as i32;
                }
                mm.rm_so = 0;
            } else if rc != 0 {
                break;
            }

            // At least one line we didn't print since match while -ABC active
            if let Some(inner_bars) = bars {
                // xputs does a new line
                println_nonklee!("{}", inner_bars);
                bars = None
            }
            matched += 1;
            TT.found = true;

            // Are we NOT showing the matching text?
            if flag.quiet {
                exit(0);
            }
            if flag.L_filenames_with_no_match || flag.l_filenames_with_a_match {
                if flag.l_filenames_with_a_match {
                    print_nonklee!("{}{}", name.to_string_lossy(), TT.outdelim);
                }
                // note: don't need to explicitly free or explicit close files
                return true;
            }

            if !flag.c_count_of_matching_lines {
                let bcount = 1
                    + offset
                    + start
                    + if flag.o_only_matching_part {
                        mm.rm_so as usize
                    } else {
                        0
                    };
                if bin {
                    println_nonklee!("Binary file {} matches", name.to_string_lossy());
                } else if flag.o_only_matching_part {
                    let vec = (&line.as_bytes()[(start + mm.rm_so as usize)..]).to_owned();
                    outline(
                        flag,
                        TT,
                        Some(&OsString::from_vec(vec)),
                        ':',
                        name,
                        lcount,
                        bcount,
                        (mm.rm_eo - mm.rm_so) as u32,
                    );
                } else {
                    let mut dl = discarded_line_buffer.pop_front();
                    while let Some(discarded_line) = dl {
                        let before = discarded_line_buffer.len() + 1;
                        outline(
                            flag,
                            TT,
                            Some(&discarded_line.str),
                            '-',
                            name,
                            lcount - before,
                            discarded_line.bcount + 1,
                            discarded_line.trim,
                        );
                        dl = discarded_line_buffer.pop_front()
                    }

                    if matched == 1 {
                        outline(
                            flag,
                            TT,
                            if flag.color.is_some() {
                                None
                            } else {
                                Some(&line)
                            },
                            ':',
                            name,
                            lcount,
                            bcount,
                            ulen as u32,
                        );
                    }

                    if flag.color.is_some() {
                        print_nonklee!("{}", TT.grey);
                        if mm.rm_so != 0 {
                            let end_idx = {
                                let init = start + mm.rm_so as usize;
                                if init > line.len() {
                                    line.len()
                                } else {
                                    init
                                }
                            };
                            print_nonklee!("{}", &line.to_string_lossy()[start..end_idx])
                        }
                        print_nonklee!("{}", TT.red);
                        let idx = start + mm.rm_so as usize;
                        if idx < line.len() {
                            xputl_bytes(
                                line.to_string_lossy()[idx..].as_bytes(),
                                (mm.rm_eo - mm.rm_so) as u32,
                            )
                        }
                    }

                    if flag.A_show_num_lines_after != 0 {
                        after = (flag.A_show_num_lines_after as u64) + 1;
                    }
                }
            }

            start += mm.rm_eo as usize;
            if mm.rm_so == mm.rm_eo {
                break;
            }
        }
        offset += len;

        if matched != 0 {
            // Finish off pending line color fragment.
            if flag.color.is_some() && !flag.o_only_matching_part {
                print_nonklee!("{}", TT.grey);
                if ulen > start {
                    xputl_bytes(&line.as_bytes()[start..], (ulen - start) as u32)
                }
                print_nonklee!("{}", TT.outdelim);
            }
            mcount += 1;
        } else {
            let mut discard = after != 0 || flag.B_show_num_lines_before != 0;

            if after != 0 {
                after -= 1;
                if after != 0 {
                    outline(flag, TT, Some(&line), '-', name, lcount, 0, ulen as u32);
                    discard = false;
                }
            }
            if discard && flag.B_show_num_lines_before != 0 {
                discarded_line_buffer.push_back(DiscardedLine {
                    str: line,
                    bcount: offset - len,
                    trim: ulen as u32,
                });
                if discarded_line_buffer.len() > flag.B_show_num_lines_before as usize {
                    discarded_line_buffer.pop_front();
                } else {
                    discard = false;
                }
                // The before variable is just keeping track of the size of dlb

                // The line = 0 is unnecessary, as Toybox just does that to prevent the free call
                // later from freeing it in dlb
            }
            // If we discarded a line while displaying context, show bars before next
            // line (but don't show them now in case that was last match in file)
            if discard && mcount != 0 {
                bars.replace("--");
            }
        }

        if flag.m_match_max_lines != 0 && mcount >= flag.m_match_max_lines {
            return true;
        }

        false
    };

    let mut stdin_handle = stdin();
    // declared first since these should outlast `reader`
    let (mut stdin_locked_handle, mut file_reader): (StdinLock, BufReader<File>);
    let reader: &mut dyn BufRead = match file_type {
        FileType::Path(file) => {
            file_reader = BufReader::new(file);
            &mut file_reader
        }
        FileType::Stdin => {
            stdin_locked_handle = stdin_handle.lock();
            &mut stdin_locked_handle
        }
    };
    let iter: SplitWithDelim<&mut dyn BufRead> = SplitWithDelim::new(reader, TT.indelim as u8);

    // get next line, check and trim delimiter
    for line in iter {
        match line {
            Ok(line) => {
                klee_block!({
                   verifier::assume(line.len() <= MAX_SYMBOLIC_FILE_SIZE);
                });
                if process_line(flag, TT, OsString::from_vec(line), &name) {
                    return;
                }
            }
            Err(err) => {
                if !flag.silent {
                    eprintln!("grep: {}: {}", name.to_str().unwrap(), err);
                }
                return;
            }
        }
    }

    if flag.L_filenames_with_no_match {
        print_nonklee!("{}{}", name.to_string_lossy(), TT.outdelim);
    } else if flag.c_count_of_matching_lines {
        outline(flag, TT, None, ':', &name, mcount as usize, 0, 1)
    }
}

fn do_grep_r(flag: &mut Flag, TT: &mut TT, path: &Path) {
    TT.tried += 1;

    if !flag.S_skip_filename_pattern.is_empty() || !flag.M_match_filename_pattern.is_empty() {
        for name in &flag.S_skip_filename_pattern {
            if path == *name {
                return;
            }
        }
        if !flag.M_match_filename_pattern.is_empty() {
            let mut found = false;
            for name in &flag.M_match_filename_pattern {
                if path == *name {
                    found = true;
                    break;
                }
            }
            if !found {
                return;
            }
        }
    }

    let metadata = if flag.R_recurse_symlink {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    let metadata = match metadata {
        Ok(data) => data,
        Err(err) => {
            if !flag.silent {
                eprintln!("grep: {}: {}", path.to_str().unwrap(), err);
            }
            return;
        }
    };

    if metadata.is_dir() {
        if !flag.exclude_dir.is_empty() {
            let name_to_use = path
                .file_name()
                .map_or_else(|| path.to_path_buf(), PathBuf::from);
            if flag.exclude_dir.contains(&name_to_use) {
                return;
            }
        }

        // "grep -r onefile" doesn't show filenames, but "grep -r onedir" should.
        if !flag.h_hide_filename {
            flag.H_force_filename = true;
        }

        let dir_iter = match fs::read_dir(path) {
            Ok(dir) => dir,
            Err(err) => {
                if !flag.silent {
                    eprintln!("grep: {}: {}", path.to_str().unwrap(), err);
                }
                return;
            }
        };

        for dir in dir_iter {
            let dir = match dir {
                Ok(dir) => dir,
                Err(_) => continue,
            };
            do_grep_r(flag, TT, &dir.path());
        }
    } else {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                if !flag.silent {
                    eprintln!("grep: {}: {}", path.to_str().unwrap(), err);
                }
                return;
            }
        };

        do_grep(flag, TT, FileType::Path(file), path);
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

    // don't try to do isatty call
    verifier::assume(flag.color.is_none());

    verifier::assume(0 <= flag.A_show_num_lines_after && flag.A_show_num_lines_after <= 4);
    verifier::assume(0 <= flag.B_show_num_lines_before && flag.B_show_num_lines_before <= 4);
    verifier::assume(0 <= flag.C_num_lines_context && flag.C_num_lines_context <= 4);
    verifier::assume(0 <= flag.m_match_max_lines && flag.m_match_max_lines <= 4);

    flag
}

#[cfg(not(feature = "verifier-klee"))]
fn get_flags() -> Flag {
    match Flag::from_args_safe() {
        Ok(flag) => flag,
        Err(err) => {
            eprintln_nonklee!("{}", err.message);
            exit(2);
        }
    }
}

fn main() {
    let mut flag: Flag = get_flags();
    let mut TT = TT::default();

    if let Some(color) = &flag.color {
        if (color.is_empty() || color == "auto") && !nix::unistd::isatty(1).unwrap_or(false) {
            flag.color = None;
        }
    }

    if flag.color.is_some() {
        TT.purple = "\x1b[35m";
        TT.cyan = "\x1b[36m";
        TT.red = "\x1b[1;31m";
        TT.green = "\x1b[1;32m";
        TT.grey = "\x1b[m";
    } else {
        TT.purple = "";
        TT.cyan = "";
        TT.red = "";
        TT.green = "";
        TT.grey = "";
    }

    if flag.R_recurse_symlink {
        flag.r_recurse = true;
    }

    if flag.A_show_num_lines_after == 0 {
        flag.A_show_num_lines_after = flag.C_num_lines_context;
    }
    if flag.B_show_num_lines_before == 0 {
        flag.B_show_num_lines_before = flag.C_num_lines_context;
    }

    TT.indelim = if !flag.z_input_nul_terminated {
        '\n'
    } else {
        '\u{0}'
    };
    TT.outdelim = if !flag.Z_output_is_nul_terminated {
        '\n'
    } else {
        '\u{0}'
    };

    // TODO: Handle egrep and fgrep?

    if flag.e_regex_to_match.is_empty() && flag.f_file_with_regex.is_none() {
        if flag.regex_or_files.is_empty() {
            if !flag.silent {
                eprintln!("grep: no REGEX");
            }
            // Grep exits with 2 for errors
            exit(2);
        }
        flag.e_regex_to_match.push(flag.regex_or_files.remove(0));
    }

    parse_regex(&mut flag, &mut TT);

    if !flag.h_hide_filename && flag.regex_or_files.len() > 1 {
        flag.H_force_filename = true;
    }

    /*
    Not implemented - we check before error pints
    if flag.silent {
      close(2);
      xopen_stdio("/dev/null", O_RDWR);
    }
     */

    if flag.r_recurse {
        // Iterate through -r arguments. Use "." as default if none provided.
        let default_args = [OsString::from(".")];
        let args = flag.regex_or_files.to_owned();
        let iter = if !args.is_empty() {
            args.iter()
        } else {
            default_args.iter()
        }
        .map(PathBuf::from);

        for path in iter {
            if path == PathBuf::from("-") {
                do_grep(&mut flag, &mut TT, FileType::Stdin, &path);
            } else {
                do_grep_r(&mut flag, &mut TT, &path);
            }
        }
    } else {
        // If no arguments, read from stdin.
        // Note: We're inlining `loopfiles_rw` from toybox/lib here, cause closures are weird
        if flag.regex_or_files.is_empty() {
            do_grep(&mut flag, &mut TT, FileType::Stdin, &PathBuf::from("-"));
        } else {
            let len = flag.regex_or_files.len();
            // avoid iterator to avoid needing to borrow
            for i in 0..len {
                let path = flag.regex_or_files[i].to_owned();
                if path == *"-" {
                    do_grep(&mut flag, &mut TT, FileType::Stdin, &PathBuf::from(&path));
                } else {
                    // loopfiles_rw checks if the file opens correctly
                    let file = match File::open(&path) {
                        Ok(file) => file,
                        Err(err) => {
                            if !flag.silent {
                                eprintln!("grep: {}: {}", path.to_string_lossy(), err);
                            }
                            continue;
                        }
                    };
                    do_grep(
                        &mut flag,
                        &mut TT,
                        FileType::Path(file),
                        &PathBuf::from(&path),
                    );
                }
            }
        }
    }

    if TT.tried >= flag.regex_or_files.len() as u32 || (flag.quiet && TT.found) {
        exit(if TT.found { 0 } else { 1 });
    } else {
        exit(2);
    }
}
