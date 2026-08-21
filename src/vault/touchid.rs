//! Touch ID via LocalAuthentication (objc2 bindings). Fail closed:
//! unavailable, failed, cancelled and internal errors all deny.

use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchIdState {
    /// Prompt available and biometrics enrolled.
    Available,
    /// Not available on this platform/hardware.
    Unavailable,
}

/// Outcome of one prompt attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptOutcome {
    Authenticated,
    Failed,
    Cancelled,
    SystemCancelled,
    Unavailable(String),
}

pub trait TouchIdPrompt: Send + Sync {
    fn state(&self) -> TouchIdState;
    fn prompt(&self, reason: &str) -> PromptOutcome;
}

/// Session cache: a short, visible, revocable user-presence window.
pub struct SessionAuthenticator {
    prompt: Box<dyn TouchIdPrompt>,
    idle: Mutex<Option<Instant>>,
    idle_window: Duration,
}

pub const DEFAULT_IDLE_WINDOW: Duration = Duration::from_secs(15 * 60);

impl SessionAuthenticator {
    pub fn new(prompt: Box<dyn TouchIdPrompt>) -> Self {
        Self {
            prompt,
            idle: Mutex::new(None),
            idle_window: DEFAULT_IDLE_WINDOW,
        }
    }

    pub fn with_window(mut self, window: Duration) -> Self {
        self.idle_window = window;
        self
    }

    pub fn invalidate(&self) {
        *self.idle.lock().unwrap() = None;
    }

    /// FAIL CLOSED: required-but-unavailable means deny (legacy returned
    /// true — the documented fail-open defect, fixed here).
    pub fn ensure_authenticated(&self, reason: &str) -> bool {
        if self.prompt.state() != TouchIdState::Available {
            return false;
        }
        let mut last = self.idle.lock().unwrap();
        if let Some(t) = *last
            && t.elapsed() < self.idle_window
        {
            return true;
        }
        match self.prompt.prompt(reason) {
            PromptOutcome::Authenticated => {
                *last = Some(Instant::now());
                true
            }
            _ => {
                *last = None;
                false
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub fn system_touch_id() -> Box<dyn TouchIdPrompt> {
    Box::new(macos::MacTouchId)
}

#[cfg(not(target_os = "macos"))]
pub fn system_touch_id() -> Box<dyn TouchIdPrompt> {
    Box::new(NoTouchId)
}

/// Non-macOS / unavailable prompt.
pub struct NoTouchId;
impl TouchIdPrompt for NoTouchId {
    fn state(&self) -> TouchIdState {
        TouchIdState::Unavailable
    }
    fn prompt(&self, _reason: &str) -> PromptOutcome {
        PromptOutcome::Unavailable("Touch ID not available on this platform".into())
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::NSString;
    use objc2_local_authentication::{
        LAContext, LAPolicy, kLAErrorBiometryLockout, kLAErrorBiometryNotAvailable,
        kLAErrorBiometryNotEnrolled, kLAErrorPasscodeNotSet, kLAErrorSystemCancel,
        kLAErrorUserCancel, kLAErrorUserFallback,
    };

    pub struct MacTouchId;

    impl MacTouchId {
        fn fresh_context() -> Retained<LAContext> {
            // A fresh context per evaluation so a previous failed attempt
            // never satisfies a later prompt.
            unsafe { LAContext::new() }
        }

        fn availability() -> TouchIdState {
            let ctx = Self::fresh_context();
            let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
            match unsafe { ctx.canEvaluatePolicy_error(policy) } {
                Ok(()) => TouchIdState::Available,
                Err(err) => {
                    let code = err.code() as i32;
                    if code == kLAErrorBiometryNotAvailable
                        || code == kLAErrorBiometryNotEnrolled
                        || code == kLAErrorBiometryLockout
                        || code == kLAErrorPasscodeNotSet
                    {
                        TouchIdState::Unavailable
                    } else {
                        // Unknown preconditions also count as unavailable;
                        // callers fail closed either way.
                        TouchIdState::Unavailable
                    }
                }
            }
        }
    }

    impl TouchIdPrompt for MacTouchId {
        fn state(&self) -> TouchIdState {
            Self::availability()
        }

        fn prompt(&self, reason: &str) -> PromptOutcome {
            let ctx = Self::fresh_context();
            let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
            if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(policy) } {
                return PromptOutcome::Unavailable(format!(
                    "biometrics unavailable: code {}",
                    e.code()
                ));
            }
            let reason_ns = NSString::from_str(reason);
            let (tx, rx) = std::sync::mpsc::channel::<(bool, Option<i32>)>();
            let tx = Mutex::new(Some(tx));
            // evaluatePolicy invokes the reply block on a private queue;
            // bridge it to a channel receive below.
            let block =
                block2::RcBlock::new(move |ok: Bool, err: *mut objc2_foundation::NSError| {
                    let code = if err.is_null() {
                        None
                    } else {
                        Some(unsafe { (*err).code() as i32 })
                    };
                    if let Some(tx) = tx.lock().unwrap().take() {
                        let _ = tx.send((ok.as_bool(), code));
                    }
                });
            let dyn_block: &block2::DynBlock<dyn Fn(Bool, *mut objc2_foundation::NSError)> = &block;
            unsafe { ctx.evaluatePolicy_localizedReason_reply(policy, &reason_ns, dyn_block) }
            match rx.recv_timeout(Duration::from_secs(120)) {
                Ok((true, _)) => PromptOutcome::Authenticated,
                Ok((false, Some(code))) => {
                    if code == kLAErrorUserCancel || code == kLAErrorUserFallback {
                        PromptOutcome::Cancelled
                    } else if code == kLAErrorSystemCancel {
                        PromptOutcome::SystemCancelled
                    } else {
                        PromptOutcome::Failed
                    }
                }
                Ok((false, None)) => PromptOutcome::Failed,
                Err(_) => PromptOutcome::Unavailable("prompt timed out".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePrompt {
        state: TouchIdState,
        outcomes: Mutex<Vec<PromptOutcome>>,
    }

    impl TouchIdPrompt for FakePrompt {
        fn state(&self) -> TouchIdState {
            self.state
        }
        fn prompt(&self, _reason: &str) -> PromptOutcome {
            self.outcomes.lock().unwrap().remove(0)
        }
    }

    fn auth(state: TouchIdState, outcomes: Vec<PromptOutcome>) -> SessionAuthenticator {
        SessionAuthenticator::new(Box::new(FakePrompt {
            state,
            outcomes: Mutex::new(outcomes),
        }))
    }

    #[test]
    fn unavailable_fails_closed() {
        let a = auth(TouchIdState::Unavailable, vec![]);
        assert!(!a.ensure_authenticated("test"), "unavailable must deny");
    }

    #[test]
    fn success_caches_within_window() {
        let a = auth(
            TouchIdState::Available,
            vec![PromptOutcome::Authenticated, PromptOutcome::Failed],
        );
        assert!(a.ensure_authenticated("test"));
        // Second call inside the window must NOT consume the failed prompt.
        assert!(a.ensure_authenticated("test"));
    }

    #[test]
    fn failure_does_not_cache() {
        let a = auth(
            TouchIdState::Available,
            vec![PromptOutcome::Cancelled, PromptOutcome::Authenticated],
        );
        assert!(!a.ensure_authenticated("test"));
        assert!(a.ensure_authenticated("test"));
    }

    #[test]
    fn invalidate_forces_reprompt() {
        let a = auth(
            TouchIdState::Available,
            vec![PromptOutcome::Authenticated, PromptOutcome::Authenticated],
        );
        assert!(a.ensure_authenticated("test"));
        a.invalidate();
        assert!(a.ensure_authenticated("test"));
    }
}
