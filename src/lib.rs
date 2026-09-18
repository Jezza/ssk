//! ssk: a high-level SSH identity manager.
//!
//! The binary in `main.rs` is a thin shell over this crate so that integration
//! tests can drive every command through the same code path.

pub mod cli;
pub mod commands;
pub mod config_file;
pub mod fsx;
pub mod identity;
pub mod json;
pub mod settings;
pub mod ssh;
pub mod state;
pub mod target;
pub mod ui;
