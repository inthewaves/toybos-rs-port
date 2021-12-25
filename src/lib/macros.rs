/// A wrapper around the [std::println] macro that is a no-op when using KLEE.
#[macro_export]
macro_rules! println_nonklee {
    () => (
        if cfg!(not(feature = "verifier-klee")) {
            println!()
        }
    );
    ($($arg:tt)*) => ({
        if cfg!(not(feature = "verifier-klee")) {
            println!($($arg)*);
        }
    })
}

/// A wrapper around the [std::print] macro that is a no-op when using KLEE.
#[macro_export]
macro_rules! print_nonklee {
    ($($arg:tt)*) => ({
        if cfg!(not(feature = "verifier-klee")) {
            print!($($arg)*);
        }
    })
}

/// A wrapper around the [std::eprintln] macro that is a no-op when using KLEE.
#[macro_export]
macro_rules! eprintln_nonklee {
    () => (
        if cfg!(not(feature = "verifier-klee")) {
            eprintln!()
        }
    );
    ($($arg:tt)*) => ({
        if cfg!(not(feature = "verifier-klee")) {
            eprintln!($($arg)*);
        }
    })
}

/// A block that only executes when running KLEE.
#[cfg(feature = "verifier-klee")]
#[macro_export]
macro_rules! klee_block {
    ($body:block) => {
        $body;
    };
}


/// A block that only executes when running KLEE.
#[cfg(not(feature = "verifier-klee"))]
#[macro_export]
macro_rules! klee_block {
    ($body:block) => {};
}

/// A wrapper around the [verification_annotations::verifier::open_merge] macro that is a no-op when
/// not using KLEE.
#[cfg(feature = "verifier-klee")]
#[macro_export]
macro_rules! klee_open_merge {
    () => (
        verification_annotations::verifier::open_merge();
    )
}

#[cfg(not(feature = "verifier-klee"))]
#[macro_export]
macro_rules! klee_open_merge {
    () => ()
}

/// A wrapper around the [verification_annotations::verifier::close_merge] macro that is a no-op
/// when not using KLEE.
#[cfg(feature = "verifier-klee")]
#[macro_export]
macro_rules! klee_close_merge {
    () => (
        verification_annotations::verifier::close_merge();
    )
}

#[cfg(not(feature = "verifier-klee"))]
#[macro_export]
macro_rules! klee_close_merge {
    () => ()
}
