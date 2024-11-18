//! `auditor` is a module including selected traits and structs for
//! the auditors. They are defined here, so they are available to the
//! macros in the `endure-macros` library.

use std::sync::Arc;

use crate::metric::SharedMetricsStore;

/// Holds global configuration for all auditors.
#[derive(Debug)]
pub struct GlobalAuditConfigContext {
    /// Sampling window size.
    ///
    /// It specifies how many samples are collected and used for computing
    /// a metrics at the given time by the auditors.
    pub sampling_window_size: usize,
}

/// Holds configurations used by the auditors.
#[derive(Debug)]
pub struct AuditConfigContext {
    /// Global configuration for all auditors.
    pub global: GlobalAuditConfigContext,
}

impl AuditConfigContext {
    /// Instantiates [`AuditConfigContext`].
    pub fn new() -> Self {
        Self {
            global: GlobalAuditConfigContext {
                sampling_window_size: 100,
            },
        }
    }

    /// Converts the [`AuditConfigContext`] to [`SharedAuditConfigContext`].
    pub fn to_shared(self) -> SharedAuditConfigContext {
        Arc::new(std::sync::RwLock::new(self))
    }
}

/// A shareable and lockable instance of the [`AuditConfigContext`].
pub type SharedAuditConfigContext = Arc<std::sync::RwLock<AuditConfigContext>>;

/// A trait that must be implemented by all auditors.
///
/// It must create the auditor instance, initialize the metrics and store the
/// configuration context pointer whenever the auditor is configurable.
pub trait CreateAuditor {
    /// Instantiates the auditor.
    ///
    /// # Parameters
    ///
    /// - `metrics_store` is the pointer to the common metrics store.
    /// - `config_context` is a pointer to the program configuration that can be
    ///   potentially modified at runtime.
    fn create_auditor(
        metrics_store: &SharedMetricsStore,
        config_context: &SharedAuditConfigContext,
    ) -> Self;
}

#[cfg(test)]
mod tests {
    use super::AuditConfigContext;

    #[test]
    fn new_audit_config_context() {
        let ctx = AuditConfigContext::new();
        assert_eq!(100, ctx.global.sampling_window_size)
    }
}