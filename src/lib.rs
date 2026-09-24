//! ssk: a high-level SSH identity manager.
//!
//! The binary in `main.rs` is a thin shell over this crate so that integration
//! tests can drive every command through the same code path.

pub mod args;
pub mod config_file;
pub mod fsx;
pub mod identity;
pub mod json;
pub mod settings;
pub mod ssh;
pub mod state;
pub mod target;
pub mod ui;

pub mod cmd {
    pub mod add;
    pub mod completions;
    pub mod config;
    pub mod copy;
    pub mod delete;
    pub mod doctor;
    pub mod hosts;
    pub mod list;
    pub mod new;
    pub mod rename;
    pub mod revoke;
    pub mod rotate;
    pub mod show;
}
