use std::io::{BufRead, Result};

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
