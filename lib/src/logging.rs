use chrono::prelude::*;

use std::sync::{Mutex, OnceLock};
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::io::{self, Write};

use log::{
    Log,
    Level, LevelFilter,
    Metadata, Record
};

use crate::BR3K_VERSION;

static LOGGER: OnceLock<Br3kLogger> = OnceLock::new();

struct Br3kLogger {
    log_console: bool,
    file: Option<Mutex<File>>,
}

impl Log for Br3kLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        if self.log_console {
            let line = format!("{}\n", record.args());
            let _ = io::stdout().write_all(line.as_bytes());
        }

        if let Some(file) = &self.file {
            let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
            let line_f = format!("[{}] [{:<5}] {}\n", ts, record.level(), record.args());
            if let Ok(mut f) = file.lock() {
                let _ = f.write_all(line_f.as_bytes());
            }
        }
    }

    fn flush(&self) {
        if self.log_console {
            let _ = io::stdout().flush();
        }

        if let Some(file) = &self.file {
            if let Ok(mut f) = file.lock() {
                let _ = f.flush();
            }
        }
    }
}

pub fn init(log_console: bool, log_file: bool) {

    let mut logger = Br3kLogger {
        file: None,
        log_console
    };

    if log_file {
        let exe_path = std::env::current_exe().expect("exe path");
        let process_name = exe_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("process");

        let pid = std::process::id();
        let log_path = PathBuf::from(format!("{}_br3k_{}.log", process_name, pid));

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("open log");

        logger.file = Mutex::new(file).into();
        println!("Logging to file: {}", log_path.display());
    }

    LOGGER.set(logger).ok();

    log::set_logger(LOGGER.get().expect("logger set")).unwrap();
    log::set_max_level(LevelFilter::Info);
}

pub fn log_header() {
    let header = format!("br3k v{BR3K_VERSION}");
    let separator = "═".repeat(header.chars().count() + 2);

    log::info!("╔{separator}╗");
    log::info!("  {header}  ");
    log::info!("╚{separator}╝");
    log::info!("");
}