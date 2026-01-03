use crate::cli::Args;
use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::thread;
use std::time::Duration;

pub type LineIter = Box<dyn Iterator<Item = Result<String>>>;

pub fn build_reader(args: &Args) -> Result<LineIter> {
    if args.stdin {
        let stdin = io::stdin();
        let reader = stdin.lock();
        return Ok(Box::new(
            BufReader::new(reader)
                .lines()
                .map(|l| l.map_err(Into::into)),
        ));
    }

    let path = args
        .file
        .as_ref()
        .ok_or_else(|| anyhow!("Provide --file <path> or --stdin"))?
        .clone();

    if args.follow {
        Ok(Box::new(FollowReader::new(path)))
    } else {
        let f = File::open(path)?;
        Ok(Box::new(
            BufReader::new(f).lines().map(|l| l.map_err(Into::into)),
        ))
    }
}

struct FollowReader {
    path: String,
    reader: BufReader<File>,
}

impl FollowReader {
    fn new(path: String) -> Self {
        let f = File::open(&path).expect("failed to open file");
        let reader = BufReader::new(f);
        Self { path, reader }
    }
}

impl Iterator for FollowReader {
    type Item = Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = String::new();

        loop {
            buf.clear();
            match self.reader.read_line(&mut buf) {
                Ok(0) => {
                    // EOF: wait and try again
                    thread::sleep(Duration::from_millis(250));
                    // Re-open to handle log rotation simply
                    if let Ok(f) = File::open(&self.path) {
                        self.reader = BufReader::new(f);
                    }
                    continue;
                }
                Ok(_) => {
                    if buf.ends_with('\n') {
                        buf.pop();
                        if buf.ends_with('\r') {
                            buf.pop();
                        }
                    }
                    return Some(Ok(buf));
                }
                Err(e) => return Some(Err(e.into())),
            }
        }
    }
}
