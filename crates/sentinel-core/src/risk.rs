use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// How much damage an action could do if it is wrong.
///
/// Risk describes the action, not the decision: a `critical` action may still
/// be allowed by policy, and a `low` one may be denied.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl Risk {
    pub const ALL: [Risk; 4] = [Risk::Low, Risk::Medium, Risk::High, Risk::Critical];

    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
            Risk::Critical => "critical",
        }
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Risk {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Risk::Low),
            "medium" => Ok(Risk::Medium),
            "high" => Ok(Risk::High),
            "critical" => Ok(Risk::Critical),
            other => Err(format!(
                "unknown risk level `{other}` (expected low, medium, high or critical)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_by_severity() {
        assert!(Risk::Low < Risk::Medium);
        assert!(Risk::Medium < Risk::High);
        assert!(Risk::High < Risk::Critical);
        assert_eq!(Risk::ALL.iter().max(), Some(&Risk::Critical));
    }

    #[test]
    fn parses_case_insensitively() {
        assert_eq!("HIGH".parse::<Risk>(), Ok(Risk::High));
        assert!("severe".parse::<Risk>().is_err());
    }
}
