//! Integration tests for the Rust Auth Service
//!
//! This file serves as the main integration test entry point.
//! All integration test modules are imported here.

mod common;
mod helpers;
mod integration;

// Import all integration test modules
pub use integration::*;
