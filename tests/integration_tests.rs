//! Integration tests for the Rust Auth Service
//!
//! This file serves as the main integration test entry point.
//! All integration test modules are imported here.

mod helpers;
mod integration;
mod common;

// Import all integration test modules
pub use integration::*;
