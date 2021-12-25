# Toybox to Rust (transliteration)

A rough port of `ls` and `grep` from [Toybox](https://github.com/landley/toybox) by trying to follow the original
structure of the C code.

# Building

Your system might need various Linux tools such as `gcc` in order to build the `libc` crates.

Run `cargo build` (or `cargo build --release` for an optimized build). The separate binaries can be found in
`target/debug/` (or `target/release/`).

Alternatively, run `cargo build --bin <programname>` to build a single binary, e.g. `cargo build --bin grep` or
`cargo build --bin ls`.

## ls: SELinux support

By default, SELinux support is disabled, so the `ls -Z` will only produce `?` as output instead of the security context.
This mirrors Toybox's configuration behavior.

To enable SELinux support, first have `libselinux-dev` (`libselinux-devel` on Fedora) and `clang` installed for
building. Then, enable the `selinux` feature while building (e.g., `cargo build --features selinux --bin ls`).

SELinux was tested on Fedora 34, which has good SELinux support that's on by default.

```
target/debug/ls -Z
unconfined_u:object_r:admin_home_t:s0 Cargo.lock
unconfined_u:object_r:admin_home_t:s0 Cargo.toml
unconfined_u:object_r:admin_home_t:s0 README.md
unconfined_u:object_r:admin_home_t:s0 rust-toolchain.toml
unconfined_u:object_r:admin_home_t:s0 src
unconfined_u:object_r:admin_home_t:s0 target
```

# KLEE

There is experimental work to run KLEE via [Rust Verification Tools](https://project-oak.github.io/rust-verification-tools/about.html).

`kcachegrind` images were obtained by following https://project-oak.github.io/rust-verification-tools/2021/03/12/profiling-rust.html:

```bash
$ cargo-verify <some args>
$ rust2calltree kleeout/main/run.istats
$ kcachegrind
```

## ls

We run KLEE on ls using `cargo-verify` with arguments passed to KLEE.

* Many of these flags are from https://project-oak.github.io/rust-verification-tools/2021/07/14/coreutils.html#more-aggressive-use-of-klee

* We use KLEE's `--posix-runtime` option to enable us to pass symbolic command arguments (`--sym-arg <len>` or
  `--sym-args <min> <max> <len>`), files (`--sym-files <num> <num-bytes>`), and stdin (`--sym-stdin <num-bytes>`).

* There is an error with `strlen` in Clap / StructOpt when using symbolic arguments; the error message shows up as
  `memory error: out of bound pointer`. Replaying the test case normally doesn't result in an error. 

  From
  https://project-oak.github.io/rust-verification-tools/2021/07/14/coreutils.html#getting-cargo-verify-and-klee-to-run-on-coreutils,
  we see that a workaround for this `strlen` error is to use `--libc=uclibc` instead of the default of `--libc=klee`.

  However, the `cargo-verify` tool includes `--libc=uclibc` by default, and KLEE prevents us from specifying multiple
  `--libc` flags.  Therefore, we use `cargo-verify`'s `--replace-backend-flags` option and add the default hardcoded
  arguments along with our changes.

A possible command for `ls`:

`cargo-verify --clean -vv --bin ls --replace-backend-flags --backend-flags='--entry-point={entry},--libc=uclibc,--silent-klee-assume,--disable-verify,--output-dir={output_dir},--simplify-sym-indices,--output-module,--max-memory=8192,--disable-inlining,--use-forked-solver,--posix-runtime,--external-calls=all,--only-output-states-covering-new,--max-sym-array-size=4096,--max-solver-time=1min,--max-time=1h,--watchdog,--max-memory-inhibit=false,--max-static-fork-pct=1,--max-static-solve-pct=1,--max-static-cpfork-pct=1,--use-batching-search,--batch-instructions=10000,{file},--sym-arg,3,A,--sym-files,1,3'`

Note that we are limiting `ls` to only printing one symbolic file.

## grep

We run KLEE on grep using the `cargo-verify` command from the Rust Verification Tools.

Because grep calls unsafe libc functions such as `regexec` and `regcomp`, parameters passed to these functions cannot
symbolic arguments. To concretize these arguments, we use KLEE's `--external-call=all` flag as documented at
https://klee.github.io/docs/options/#external-call-policy

Many of these options are the same as the ones used to run for ls; explanations for those arguments in ls apply here as
well.

`cargo-verify --clean -vv --bin grep --replace-backend-flags --backend-flags='--entry-point={entry},--libc=uclibc,--silent-klee-assume,--disable-verify,--output-dir={output_dir},--simplify-sym-indices,--output-module,--max-memory=8192,--disable-inlining,--use-forked-solver,--posix-runtime,--external-calls=all,--only-output-states-covering-new,--max-sym-array-size=4096,--max-solver-time=30s,--max-time=1h,--watchdog,--max-memory-inhibit=false,--max-static-fork-pct=1,--max-static-solve-pct=1,--max-static-cpfork-pct=1,--use-batching-search,--batch-instructions=10000,{file},--sym-args,0,1,4,--sym-arg,3,--sym-files,1,4,--sym-stdin,6'`

Note that in all the following runs, KLEE will run out of memory or hit the time limit of 1 hour.

### Bugs found by KLEE

#### Passing "empty" files for `-f`

KLEE discovered that using a file for the `-f` flag containing `b'\x00\n\n\n'` (hex:0x000a0a0a) results in a crash:

```bash
$ echo 0x000a0a0a | xxd -r > crash-f-flag.txt
$ target/debug/grep -f crash-f-flag.txt
thread 'main' panicked at 'called `Option::unwrap()` on a `None` value', src/lib/xwrap.rs:33:36
```

Note that Toybox doesn't crash with this file.

This is mitigated in commit by adding C-style checks for empty strings (determining if the first byte is not the NUL
byte).

#### Passing odd files for `-f`

Using a file for the `-f` flag containing `b'\x01\x01\x00\n'` (hex: 0x0101000a) results in a panic:

```bash
$ echo 0x0101000a | xxd -r > A
$ target/debug/grep -fA
thread 'main' panicked at 'called `Option::unwrap()` on a `None` value', src/lib/xwrap.rs:42:36
```

`ktest-tool` reports the concrete test case:

```bash
$ ktest-tool a4-kleeout/grep-1hr/test000074.ktest 
ktest file : 'a4-kleeout/grep-1hr/test000074.ktest'
args       : ['.../target/x86_64-unknown-linux-gnu/debug/deps/grep-359f1dc5e38ec40f.link.patch-init-feat.bc', '--sym-args', '0', '1', '4', '--sym-arg', '3', '--sym-files', '1', '4', '--sym-stdin', '6']
num objects: 7
object 0: name: 'n_args'
object 0: size: 4
object 0: data: b'\x00\x00\x00\x00'
object 0: hex : 0x00000000
object 0: int : 0
object 0: uint: 0
object 0: text: ....
object 1: name: 'arg00'
object 1: size: 4
object 1: data: b'-fA\xff'
object 1: hex : 0x2d6641ff
object 1: int : -12491219
object 1: uint: 4282476077
object 1: text: -fA.
object 2: name: 'A-data'
object 2: size: 4
object 2: data: b'\x01\x01\x00\n'
object 2: hex : 0x0101000a
object 2: int : 167772417
object 2: uint: 167772417
object 2: text: ....
object 3: name: 'A-data-stat'
object 3: size: 144
object 3: data: b'\x10\xca\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\xa4\x81\x00\x00\xe8\x03\x00\x00\xe8\x03\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x10\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xd7\xc3\x8ca\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff \xc5\x8ca\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff \xc5\x8ca\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
object 3: hex : 0x10ca00000000000001000000ffffffff0100000000000000a4810000e8030000e8030000ffffffff0000000000000000ffffffffffffffff0010000000000000ffffffffffffffffd7c38c6100000000ffffffffffffffff20c58c6100000000ffffffffffffffff20c58c6100000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
object 3: text: ...........................................................................a............ ..a............ ..a....................................
object 4: name: 'stdin'
object 4: size: 6
object 4: data: b'\x00\x00\x00\x00\x00\x00'
object 4: hex : 0x000000000000
object 4: text: ......
object 5: name: 'stdin-stat'
object 5: size: 144
object 5: data: b'\x10\xca\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\xa4\x81\x00\x00\xe8\x03\x00\x00\xe8\x03\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x10\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xd7\xc3\x8ca\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff \xc5\x8ca\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff \xc5\x8ca\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
object 5: hex : 0x10ca00000000000001000000ffffffff0100000000000000a4810000e8030000e8030000ffffffff0000000000000000ffffffffffffffff0010000000000000ffffffffffffffffd7c38c6100000000ffffffffffffffff20c58c6100000000ffffffffffffffff20c58c6100000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
object 5: text: ...........................................................................a............ ..a............ ..a....................................
object 6: name: 'model_version'
object 6: size: 4
object 6: data: b'\x01\x00\x00\x00'
object 6: hex : 0x01000000
object 6: int : 1
object 6: uint: 1
object 6: text: ....
```

Toybox doesn't crash here.

The fix was to just treat it like how Toybox does it; we just interpret it as bytes, and let `regcomp` handle parsing
the NUL byte itself. Probably not as safe though.

We've also discovered through this bug that our `parse_regex_to_cstr` function didn't properly handle intermediate NUL
bytes. The `read_until` includes the NUL byte delimiter, which results in the second retry of `CString::new` to also
fail.

#### Subtraction underflow

Much of the code to ensure NUL termination for libc calls introduced subtraction underflow / out-of-bound access bugs,
as it usually involved checking whether `vec[vec.len() - 1] != 0` or similar conditions. For example:

```rust
let input: Vec<u8> = {
    let mut buf: Vec<u8> = string.as_bytes().to_vec();
    // Needs NUL termination. This is an issue with KLEE.
    if buf.len() == 0 || buf[buf.len() - 1] != 0 {
        buf.push(0);
    }
    buf
};
```

KLEE discovered this bug:

```bash
$ cargo build --bin grep --target x86_64-unknown-linux-gnu --features verifier-klee
$ RUST_BACKTRACE=1 klee-replay target/x86_64-unknown-linux-gnu/debug/grep kleeout/main/test000002.ktest 
KLEE-REPLAY: NOTE: Test file: kleeout/main/test000002.ktest
KLEE-REPLAY: NOTE: Arguments: "target/x86_64-unknown-linux-gnu/debug/grep" ")" 
KLEE-REPLAY: NOTE: Storing KLEE replay files in /tmp/klee-replay-JyVhPs
KLEE-REPLAY: NOTE: Creating file /tmp/klee-replay-JyVhPs/A of length 4
KLEE-REPLAY: NOTE: Creating file /tmp/klee-replay-JyVhPs/fd0 of length 6
KLEE-REPLAY: WARNING: check_file stdin: dev mismatch: 52 vs 51728
KLEE-REPLAY: WARNING: check_file A: dev mismatch: 52 vs 51728
thread 'main' panicked at 'attempt to subtract with overflow', src/lib/lib.rs:112:16
...
note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
KLEE-REPLAY: NOTE: EXIT STATUS: ABNORMAL 101 (1 seconds)
KLEE-REPLAY: NOTE: removing /tmp/klee-replay-JyVhPs
```

We fixed this by ensuring a non-empty vector before doing the subtraction:

```rust
let input: Vec<u8> = {
    let mut buf: Vec<u8> = string.as_bytes().to_vec();
    // Needs NUL termination. This is an issue with KLEE.
    if buf.len() == 0 || buf[buf.len() - 1] != 0 {
        buf.push(0);
    }
    buf
};
```

# Idiomatic revisions

## ls

### SELinux security context retrieval

Main idioms used:

* Rust By Example: [Block expressions](https://doc.rust-lang.org/rust-by-example/expression.html), [if
  let](https://doc.rust-lang.org/rust-by-example/flow_control/if_let.html)
* Conditional branches based on build configuration

The Toybox C code to obtain the SELinux context and put it in `new->extra` is as follows:

```c
if (FLAG(Z)) {
  if (!CFG_TOYBOX_LSM_NONE) {
    // Linux doesn't support fgetxattr(2) on O_PATH file descriptors (though
    // bionic works around that), and there are no *xattrat(2) calls, so we
    // just use lgetxattr(2).
    char *path = dirtree_path(new, 0);

    (FLAG(L) ? lsm_get_context : lsm_lget_context)(path,(char **)&new->extra);
    free(path);
  }
  if (CFG_TOYBOX_LSM_NONE || !new->extra) new->extra = (long)xstrdup("?");
}
```

We can rewrite it in Rust and make it more idiomatic:

```rust
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
```

We could use a `match` here, but since an `Option` has only two possibilities, using `if let` saves us some indentation.

### Directory trees

Main idioms used:
* Rust By Example: [New type idiom](https://doc.rust-lang.org/rust-by-example/generics/new_types.html)

Toybox uses a struct to keep directory tree node information in a tree. The nodes keeps track of their children,
siblings, and parent. Children and siblings are treated as a linked list:

```C
struct dirtree {
  struct dirtree *next, *parent, *child;
  long extra; // place for user to store their stuff (can be pointer)
  char *symlink;
  int dirfd;
  struct stat st;
  char again, name[];
};
```

For our Rust code, in order to simplify this with respect to borrow checking, we use a tree backed by a `HashMap` ([Rust
By Example: HashMap](https://doc.rust-lang.org/rust-by-example/std/hash.html)) along with an autoincrementing key to
serve as node "addresses" (`impl` blocks not shown).

```rust
#[derive(Debug, Hash, Copy, Clone, Eq, PartialEq)]
pub struct TreeIdx(usize);

/// A HashMap-based tree that uses an auto-incrementing integer ID as node "pointers" (`TreeIdx`).
/// Using integers as pointers makes it cheap to copy around and store references (as long as there
/// is a reference to a tree).
///
/// Note: Removal is not supported (although easy to do)
#[derive(Debug)]
pub struct MapTree<T> {
    all_nodes: HashMap<TreeIdx, Node<T>>,
    autoincrement_idx: TreeIdx,
}

#[derive(Debug, Clone)]
pub struct Node<T> {
    idx: TreeIdx,
    value: T,
    parent: Option<TreeIdx>,
    children: Vec<TreeIdx>,
}
```

Keeping children in vectors makes it easier to iterate idiomatically using iterators.

We use this struct as the type parameter:

```rust
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
```

Note that we have `mtime_to_use` and `st_blocks_to_use`. Toybox's ls code modifies its `stat` field (`struct stat`
contains the same information as Rust's `Netadata`) directly:

```C
static int filter(struct dirtree *new)
{
  ...
  if (FLAG(u)) new->st.st_mtime = new->st.st_atime;
  if (FLAG(c)) new->st.st_mtime = new->st.st_ctime;
  new->st.st_blocks >>= 1; // Use 1KiB blocks rather than 512B blocks.
  ...
}
```

Because Rust's `Metadata` struct fields are private, so they're not modifiable even as a mutable variable / reference.
We just put any modifiable items as the struct field itself and use that for display purposes. An alternative to this
would be to use unsafe rust to call the `fstatat` or `statx` functions directly and get a `stat` struct that can be
modified; however, it's better to stick with what the `std` offers, as avoiding unsafe Rust is a priority.

An alternative tree implementation would be to follow [one of the examples from the Rust
book](https://doc.rust-lang.org/book/ch15-06-reference-cycles.html#adding-a-reference-from-a-child-to-its-parent) and
use `RefCell`s, `Rc`s, and `Weak` references:

```rust
use std::cell::RefCell;
use std::rc::{Rc, Weak};

#[derive(Debug)]
struct Node {
    value: i32,
    parent: RefCell<Weak<Node>>,
    children: RefCell<Vec<Rc<Node>>>,
}
```

However, the `MapTree` implementation served to be easier to code and works better with the compiler (as `RefCell`
borrow checking is only enforced at runtime instead of compile-time).

### Directory traversal

Main idioms used:

* Rust By Example: [Tuple destructuring](https://doc.rust-lang.org/rust-by-example/primitives/tuples.html),
  [`match`](https://doc.rust-lang.org/rust-by-example/flow_control/match.html), [std library
  types](https://doc.rust-lang.org/rust-by-example/std.html), [blocks as
  expressions](https://doc.rust-lang.org/rust-by-example/expression.html),
* Iterators and method chaining, enums

`dirtree_recurse` was written with more idiomatic Rust.

* Original C code:
  
  ```C
  int dirtree_recurse(struct dirtree *node,
            int (*callback)(struct dirtree *node), int dirfd, int flags)
  {
    struct dirtree *new, **ddt = &(node->child);
    struct dirent *entry;
    DIR *dir = 0;
  
    // Why doesn't fdopendir() support AT_FDCWD?
    if (AT_FDCWD == (node->dirfd = dirfd)) dir = opendir(".");
    else if (node->dirfd != -1) dir = fdopendir(node->dirfd);
    if (!dir) {
      if (!(flags & DIRTREE_SHUTUP)) {
        char *path = dirtree_path(node, 0);
        perror_msg_raw(path);
        free(path);
      }
      close(node->dirfd);
  
      return flags;
    }
  
    // according to the fddir() man page, the filehandle in the DIR * can still
    // be externally used by things that don't lseek() it.
  
    while ((entry = readdir(dir))) {
      if ((flags&DIRTREE_PROC) && !isdigit(*entry->d_name)) continue;
      if (!(new = dirtree_add_node(node, entry->d_name, flags))) continue;
      if (!new->st.st_blksize && !new->st.st_mode)
        new->st.st_mode = entry->d_type<<12;
      new = dirtree_handle_callback(new, callback);
      if (new == DIRTREE_ABORTVAL) break;
      if (new) {
        *ddt = new;
        ddt = &((*ddt)->next);
      }
    }
  
    if (flags & DIRTREE_COMEAGAIN) {
      node->again |= 1;
      flags = callback(node);
    }
  
    // This closes filehandle as well, so note it
    closedir(dir);
    node->dirfd = -1;
  
    return flags;
  }
  ```
  
  The way that `ls` works in Toybox is that it tends to open a directory file descriptor and then use it to open child
  files by the filenames inside the directory.

* For our Rust code, we can use `std` library's `read_dir` instead of `opendir` or `fdopendir`. We're also using
  canonical path names as opposed to passing around a parent file descriptor and opening child files via the child's
  name.

  We have to account for the fact that the `std` library's `read_dir` does not include the current directory and parent
  directories as entries.

  ```rust
  /// Toybox uses the `readdir` system call, which includes "." and ".."; however, Rust's
  /// std `read_dir` does not include them.
  static LINUX_READDIR_EXTRA_BEGINNING: [&str; 2] = [".", ".."];
  ```

  We then set about recreating the `dirtree_recurse` function. Notice that `.` and `..` are chained to the front of the
  directory contents iterator. We're also using a `CallbackResult` enum instead of integer return codes to determine 
  what to do about the recursion, and we're using function parameters instead of integer flags.

  ```rust
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
                      eprintln!(
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
          match create_node(&entry, follow_symlinks, keep_failed_metadata) {
              Ok(new_node) => {
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
  }
  ```
  
  `ls` does not use `DIRTREE_COMEAGAIN`, `DIRTREE_RECURSE`, or `DIRTREE_PROC`; for simplicity, those features have been
  left out of the `ls` implementation.

Some alternatives to this would be

* We could use the `bitflags` crate instead of having `dont_warn_metadata_fails`, `follow_symlinks`, and
  `keep_failed_metadata` passed as function parameters. However, we wanted to limit the number of external crates.
* We could use unsafe calls to `libc` functions to read the directory to get `.` and `..` included in the directory
  listing, but we want to avoid unsafe Rust. Using the `std` library is safe and idiomatic.

## grep

### Regex expression parsing

Main idioms used:
* Rust By Example: [if let](https://doc.rust-lang.org/rust-by-example/flow_control/if_let.html),
  [`match` guards](https://doc.rust-lang.org/rust-by-example/flow_control/match/guard.html),
  [std library types](https://doc.rust-lang.org/rust-by-example/std.html),
  [variable shadowing](https://doc.rust-lang.org/rust-by-example/variable_bindings/scope.html)

The original C code has a lot of verbose linked list code to move the lines of the `-f` file and the `-e` arguments into
one linked list:

```c
struct arg_list *al, *new, *list = NULL;
char *s, *ss;

// Add all -f lines to -e list. (Yes, this is leaking allocation context for
// exit to free. Not supporting nofork for this command any time soon.)
al = TT.f ? TT.f : TT.e;
while (al) {
  if (TT.f) {
    if (!*(s = ss = xreadfile(al->arg, 0, 0))) {
      free(ss);
      s = 0;
    }
    printf("Value of file is [%s]\n", s);
  } else s = ss = al->arg;

  // Advance, when we run out of -f switch to -e.
  al = al->next;
  if (!al && TT.f) {
    TT.f = 0;
    al = TT.e;
  }
  if (!s) continue;

  // Split lines at \n, add individual lines to new list.
  do {
    printf("Adding [%s] to regex\n", s);
    ss = FLAG(z) ? 0 : strchr(s, '\n');
    if (ss) *(ss++) = 0;
    new = xmalloc(sizeof(struct arg_list));
    new->next = list;
    new->arg = s;
    list = new;
    s = ss;
  } while (ss && *s);
}
TT.e = list;
```

This is simplified and made more readable using `std` library functions such as `fs::read`, `Vec`s, `match` expressions,
and for-each loops / iterators.

```rust
// Add all -f lines to -e list.
if let Some(file_with_regex) = &flag.f_file_with_regex {
    // Toybox reads the entire contents of the regex file.
    match fs::read(file_with_regex) {
        Ok(file_bytes) if !file_bytes.is_empty() => {
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
            Err(_) => {
                panic!(
                    "I/O errors shouldn't happen as we are reading from an in-memory string!"
                )
            }
        }
    }
}
flag.e_regex_to_match = split_regex_lines_list;
```

### Discarded line buffers

Main idioms used:
* Rust By Example: [Std library types](https://doc.rust-lang.org/rust-by-example/std.html), [while
  let](https://doc.rust-lang.org/rust-by-example/flow_control/while_let.html)

The original Toybox C code maintains a limited-size queue using doubly-linked lists when the `-B` flag is specified to
show a specified number of lines before a match.

* Adding lines with information to the queue:

  ```C
  unsigned *uu, ul = (ulen|3)+1;
  line = xrealloc(line, ul+8);
  uu = (void *)(line+ul);
  uu[0] = offset-len;
  uu[1] = ulen;
  dlist_add(&dlb, line);
  line = 0;
  if (++before>TT.B) {
    struct double_list *dl;
  
    dl = dlist_pop(&dlb);
    free(dl->data);
    free(dl);
    before--;
  } else discard = 0;
  ```
  
  Notice how the `before` variable is used to manually track the size of the queue. The `xrealloc(line, ul+8)` is used
  to store extra information about the line without using a struct. This code also handles popping off lines when the
  queue size is over the limit (`TT.B` is the flag value of the number of lines to show before a match).

* Popping lines off the queue to print them:

  ```C
  while (dlb) {
    struct double_list *dl = dlist_pop(&dlb);
    unsigned *uu = (void *)(dl->data+(strlen(dl->data)|3)+1);
  
    outline(dl->data, '-', name, lcount-before, uu[0]+1, uu[1]);
    free(dl->data);
    free(dl);
    before--;
  }
  ```

Our idiomatic changes for our Rust code are as follows:

* Use the `std` library's [`VecDeque<T>`](https://doc.rust-lang.org/std/collections/struct.VecDeque.html) and a struct:

  ```rust
  #[derive(Debug)]
  struct DiscardedLine {
      str: OsString,
      bcount: usize,
      trim: u32,
  }

  let mut discarded_line_buffer: VecDeque<DiscardedLine> = VecDeque::new();
  ```
  
* Adding lines with information to the queue via `VecDeque` operations:

  ```rust
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
  ```
  
  The `before` variable is now redundant, as it can be easily obtained via `iscarded_line_buffer.len()`.
  
* Popping lines off the queue to print them:

  ```rust
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
  ```

Some alternatives for to a `VecDeque` include using
[`std::collections::LinkedList`](https://doc.rust-lang.org/std/collections/struct.LinkedList.html). However, using a
linked list could be less memory-efficient, because linked list nodes contain unneeded information in the context of a
deque (e.g., intermediate nodes do not need to be removed, so no need to keep track of front and back pointers).

### Match statements

Instead of checking manually if an array access is out of bounds, we can use `get` and a match statement:

```diff
                 if c == 0 as char {
-                    c = start_array[(mm.rm_eo) as usize] as char;
+                    // If this is out of bounds, like mm.rm_eo == start_array.len(), Toybox will
+                    // not segfault or crash. (e.g., if mm.rm_eo == start_array.len(), then c will
+                    // take the nul byte at the end of the string. Weird semantics, but let's
+                    // preserve them.
+                    c = match start_array.get((mm.rm_eo) as usize) {
+                        None => c,
+                        Some(char) => *char as char,
+                    };
+
                     if !c.is_alphanumeric() && c != '_' {
                         c = 0 as char;
                     }
```

The alternative would be to panic, but Toybox does not do this as explained by the comment.

### Closures

Idioms used:

* Rust by Example: [Closures](https://doc.rust-lang.org/rust-by-example/fn/closures.html)

The main loop body to process a line of input in `do_grep` has been converted from a local function to a closure:

```diff
@@ -357,28 +366,25 @@ fn do_grep(flag: &mut Flag, TT: &mut TT, file_type: FileType, name: &Path) {
     let mut discarded_line_buffer: VecDeque<DiscardedLine> = VecDeque::new();
     let mut mcount = 0;
     let mut after = 0;
-    let mut before = 0;
+    // Before is not used, because it's basically keeping track of discarded_line_buffer's size
+    // let mut before = 0;
 
     /// Returns whether the outer function should also return
-    fn for_each_line(
-        flag: &mut Flag,
-        TT: &mut TT,
-        line: &OsString,
-        name: &Path,
-        bin: bool,
-        matched: &mut i32,
-        offset: &mut usize,
-        lcount: &mut usize,
-        bars: &mut Option<&str>,
-        discarded_line_buffer: &mut VecDeque<DiscardedLine>,
-        mcount: &mut u64,
-        after: &mut u64,
-        before: &mut u64,
-    ) -> bool {
-        *lcount += 1;
-        *matched = 0;
-
-        let ulen = line.len() + 1;
+    let mut process_line = |flag: &mut Flag, TT: &mut TT, line: &OsString, name: &Path| -> bool {
+        lcount += 1;
+        matched = 0;
+
+        let len = line.as_bytes().len();
+
+        let line = if line.as_bytes().ends_with(&[TT.indelim as u8]) {
+            let mut line_without_delim = line.as_bytes().to_vec();
+            line_without_delim.pop();
+            OsString::from_vec(line_without_delim)
+        } else {
+            line.to_owned()
+        };
+
+        let ulen = line.as_bytes().len();
 
         for shoe in &mut TT.reg {
             shoe.recheck = 0;
```


Using a closure here lets us capture the outer variables without needing to pass them as mutable references into a local
function. An alternative would be to inline this closure; however, a local function / clousre was used here in the first
place to save indentation space.

### Use borrowed types for arguments

This addresses [Use borrowed types for arguments in Rust Design
Patterns](https://rust-unofficial.github.io/patterns/idioms/coercion-arguments.html).

```diff
diff --git a/src/grep.rs b/src/grep.rs
index c38a3af..d691895 100644
--- a/src/grep.rs
+++ b/src/grep.rs
@@ -162,7 +162,7 @@ struct Reg {
 }
 
 impl Reg {
-    fn new(regex: &OsString, flags: i32) -> Reg {
+    fn new(regex: &OsStr, flags: i32) -> Reg {
         let mut regex_compiled: libc::regex_t = unsafe { mem::zeroed() };
         xregcomp(&mut regex_compiled, regex, flags);
         Reg {
```

```diff
diff --git a/src/lib/xwrap.rs b/src/lib/xwrap.rs
index ca32493..70ae5d6 100644
--- a/src/lib/xwrap.rs
+++ b/src/lib/xwrap.rs
@@ -1,14 +1,14 @@
-use std::ffi::{CString, OsString};
+use std::ffi::{CString, OsStr};
 use std::io::BufRead;
 use std::os::unix::ffi::OsStrExt;
 use std::process::exit;
 
 /// Put string with length (does not append newline)
-pub fn xputl(s: &OsString, len: u32) {
+pub fn xputl(s: &OsStr, len: u32) {
     xputl_bytes(s.as_bytes(), len);
 }
 
-fn parse_regex_to_cstr(regex: &OsString) -> Option<CString> {
+fn parse_regex_to_cstr(regex: &OsStr) -> Option<CString> {
     match CString::new(regex.as_bytes()) {
         Ok(cstr) => Some(cstr),
         Err(_) => {
@@ -22,7 +22,7 @@ fn parse_regex_to_cstr(regex: &OsString) -> Option<CString> {
     }
 }
 
-pub fn xregcomp(preg: *mut libc::regex_t, regex: &OsString, cflags: i32) {
+pub fn xregcomp(preg: *mut libc::regex_t, regex: &OsStr, cflags: i32) {
     let mut cflags = cflags;
     let regex_cstr = if regex.is_empty() {
         cflags |= libc::REG_EXTENDED;

```

There aren't really alternatives for this change; it makes the code more flexible overall.

### On-stack dynamic dispatch

This covers
[On-Stack Dynamic Dispatch from Rust Design Patterns](https://rust-unofficial.github.io/patterns/idioms/on-stack-dyn-dispatch.html).

Previous code for choosing between reading from a file or stdin involved a lot of duplicate code:

```rust
// get next line, check and trim delimiter
match file_type {
    FileType::Path(file) => {
        for line in BufReader::new(file).split(TT.indelim as u8) {
            match line {
                Ok(line) => {
                    if for_each_line(
                        flag,
                        TT,
                        &OsString::from_vec(line),
                        &name,
                        bin,
                        &mut matched,
                        &mut offset,
                        &mut lcount,
                        &mut bars,
                        &mut discarded_line_buffer,
                        &mut mcount,
                        &mut after,
                        &mut before,
                    ) {
                        return;
                    }
                }
                Err(err) => {
                    eprintln!("grep: {}: {}", name.to_str().unwrap(), err);
                    return;
                }
            }
        }
    }
    FileType::Stdin => {
        for line in stdin().split(TT.indelim as u8) {
            match line {
                Ok(line) => {
                    if for_each_line(
                        flag,
                        TT,
                        &OsString::from_vec(line),
                        &name,
                        bin,
                        &mut matched,
                        &mut offset,
                        &mut lcount,
                        &mut bars,
                        &mut discarded_line_buffer,
                        &mut mcount,
                        &mut after,
                        &mut before,
                    ) {
                        return;
                    }
                }
                Err(err) => {
                    eprintln!("grep: {}: {}", name.to_str().unwrap(), err);
                    return;
                }
            }
        }
    }
}
```

The revised code (note that we no longer use `BufRead.split` as it was leaving out delimiters) makes use of dynamic
dispatch:

```rust
// declared first since these should outlast `reader`
let (mut stdin_locked_handle, mut file_reader): (StdinLock<'static>, BufReader<File>);
let reader: &mut dyn BufRead = match file_type {
    FileType::Path(file) => {
        file_reader = BufReader::new(file);
        &mut file_reader
    }
    FileType::Stdin => {
        stdin_locked_handle = stdin_locked();
        &mut stdin_locked_handle
    }
};
let iter: SplitWithDelim<&mut dyn BufRead> = SplitWithDelim::new(reader, TT.indelim as u8);

// get next line, check and trim delimiter
for line in iter {
    match line {
        Ok(line) => {
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
```

Alternatives:

* We could use something like an enum or the `either` crate instead of having it so that one variable is left
  uninitialized. However, the former would likely generate some bloat and more verbosity as more match statements would 
  have to be used, and the latter would mean more reliance on external crates.

  Rust also already has compile-time checks for possible uses of uninitialized variables
  (https://doc.rust-lang.org/error-index.html#E0381).

* Initially, `stdin_locked` was added as a special case to the `SplitWithDelim` struct:

  ```rust
  let iter: SplitWithDelim<BufReader<File>> = match file_type {
      FileType::Path(file) => SplitWithDelim::new(BufReader::new(file), TT.indelim as u8),
      FileType::Stdin => SplitWithDelim::from_stdin_locked(TT.indelim as u8),
  };
  ```

  The `bufreader_delim` module would be rewritten like so:

  ```rust
  use std::io::{stdin_locked, BufRead, Result, StdinLock};
  
  /// An iterator over the contents of an instance of BufRead split on a particular byte.
  ///
  /// This is a modification of [std::io::Split] to allow its `split` function to
  /// include the delimiter.
  #[derive(Debug)]
  pub struct SplitWithDelim<B> {
      buf: Buf<B>,
      delim: u8,
  }
  
  #[derive(Debug)]
  enum Buf<B> {
      BufRead(B),
      StdinLocked(StdinLock<'static>),
  }
  
  impl<B: BufRead> SplitWithDelim<B> {
      pub fn new(buf: B, delim: u8) -> SplitWithDelim<B> {
          SplitWithDelim {
              buf: Buf::BufRead(buf),
              delim,
          }
      }
  
      pub fn from_stdin_locked(delim: u8) -> SplitWithDelim<B> {
          SplitWithDelim {
              buf: Buf::StdinLocked(stdin_locked()),
              delim,
          }
      }
  }
  
  impl<B: BufRead> Iterator for SplitWithDelim<B> {
      type Item = Result<Vec<u8>>;
  
      fn next(&mut self) -> Option<Result<Vec<u8>>> {
          let mut buf = Vec::new();
  
          fn handle_buf_result(buf: Vec<u8>, res: Result<usize>) -> Option<Result<Vec<u8>>> {
              match res {
                  Ok(0) => None,
                  Ok(_n) => {
                      // BEGIN MODIFICATION FROM STD
                      // if buf[buf.len() - 1] == self.delim {
                      //     buf.pop();
                      // }
                      // END MODIFICATION FROM STD
                      Some(Ok(buf))
                  }
                  Err(e) => Some(Err(e)),
              }
          }
  
          match &mut self.buf {
              Buf::BufRead(bufreader) => {
                  let res = bufreader.read_until(self.delim, &mut buf);
                  handle_buf_result(buf, res)
              }
              Buf::StdinLocked(stdin_lock) => {
                  let res = stdin_lock.read_until(self.delim, &mut buf);
                  handle_buf_result(buf, res)
              }
          }
      }
  }
  ```

  In this way, the type returned would be `SplitWithDelim<BufReader<File>>`,  even if stdin was used for input. This
  satisfies the type constraints.
  
  However, rewriting `SplitWithDelim` to add `StdinLock` as a special case could bloat the resulting code (it's already
  using a new enum, `Buf<B>`).

  For reference, the current module is as follows (and is much more succinct):

  ```rust
  use std::io::{stdin_locked, BufRead, Result, StdinLock};
  
  /// An iterator over the contents of an instance of BufRead split on a particular byte.
  ///
  /// This is a modification of [std::io::Split] to allow its `split` function to
  /// include the delimiter.
  #[derive(Debug)]
  pub struct SplitWithDelim<B> {
      buf: B,
      delim: u8,
  }
  
  impl<B: BufRead> SplitWithDelim<B> {
      pub fn new(buf: B, delim: u8) -> SplitWithDelim<B> {
          SplitWithDelim { buf, delim }
      }
  }
  
  impl<B: BufRead> Iterator for SplitWithDelim<B> {
      type Item = Result<Vec<u8>>;
  
      fn next(&mut self) -> Option<Result<Vec<u8>>> {
          let mut buf = Vec::new();
          match self.buf.read_until(self.delim, &mut buf) {
              Ok(0) => None,
              Ok(_n) => {
                  // BEGIN MODIFICATION FROM STD
                  // if buf[buf.len() - 1] == self.delim {
                  //     buf.pop();
                  // }
                  // END MODIFICATION FROM STD
                  Some(Ok(buf))
              }
              Err(e) => Some(Err(e)),
          }
      }
  }
  ```

* We could have also used `Box`, but this results in a heap allocation (and multiple heap allocations if grep is opening
  multiple files). This can adversely affect performance of the program.
