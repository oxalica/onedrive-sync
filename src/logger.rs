use colored::{Color, Colorize};
use indicatif::ProgressBar;
use log::{Log, Metadata, Record};
use once_cell::sync::OnceCell;
use std::{sync::Mutex, time::SystemTime};

pub static LOGGER: OnceCell<Logger> = OnceCell::new();

#[derive(Debug)]
pub struct Logger {
    env_logger: env_logger::Logger,
    bar: Mutex<Option<ProgressBar>>,
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.env_logger.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.env_logger.matches(record) {
            return;
        }
        let lvl = record.level();
        let lvl_color = match lvl {
            log::Level::Trace => Color::Cyan,
            log::Level::Debug => Color::Blue,
            log::Level::Info => Color::Green,
            log::Level::Warn => Color::Yellow,
            log::Level::Error => Color::Red,
        };
        let msg = format!(
            "[{} {:5} {}] {}",
            humantime::format_rfc3339_millis(SystemTime::now()),
            lvl.to_string().color(lvl_color),
            record.module_path().unwrap_or("<unknown>"),
            record.args(),
        );
        match &*self.bar.lock().unwrap() {
            Some(bar) => bar.println(msg),
            None => eprintln!("{}", msg),
        }
    }

    fn flush(&self) {}
}

impl Logger {
    pub fn init() {
        let this = Self {
            env_logger: env_logger::Logger::from_default_env(),
            bar: Mutex::new(None),
        };
        LOGGER.set(this).unwrap();
        let logger = LOGGER.get().unwrap();

        log::set_logger(logger).unwrap();
        log::set_max_level(logger.env_logger.filter());
        log::warn!("foo");
    }

    pub fn attach_to(&self, bar: ProgressBar) -> LogRedirectGuard<'_> {
        *self.bar.lock().unwrap() = Some(bar);
        LogRedirectGuard { logger: self }
    }
}

pub struct LogRedirectGuard<'a> {
    logger: &'a Logger,
}

impl Drop for LogRedirectGuard<'_> {
    fn drop(&mut self) {
        *self.logger.bar.lock().unwrap() = None;
    }
}
