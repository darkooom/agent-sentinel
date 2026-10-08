//! Runtime wiring for agent-sentinel: where policies and state live, the
//! evaluation engine, session grants, agent adapters and command execution.

pub mod adapters;
pub mod discovery;
mod engine;
pub mod exec;
pub mod install;
mod paths;
pub mod session;

pub use engine::{Engine, Evaluation};
pub use paths::Paths;
