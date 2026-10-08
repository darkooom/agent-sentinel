//! Core types and analysis for agent-sentinel.
//!
//! The flow is: an [`Action`] (what an agent wants to do) is analyzed into an
//! [`Analysis`] (findings, risk, and facts such as paths and hosts). The
//! policy crate turns an analysis into a decision. Nothing in this crate
//! decides whether an action is allowed.

mod action;
mod analysis;
pub mod command;
mod context;
pub mod detect;
pub mod display;
mod finding;
pub mod paths;
mod risk;
pub mod secrets;
pub mod shell;

pub use action::{Action, ActionKind};
pub use analysis::{analyze, Analysis, CommandFact, Facts, Host};
pub use context::AnalysisContext;
pub use finding::{catalog, Finding, FindingSpec};
pub use risk::Risk;
