use chrono::{DateTime, Local};

/// Deferred timestamp creation.
///
/// Is used to ensure that a log record that is sent to multiple outputs
/// (in maybe different formats) always uses the same timestamp.
#[derive(Debug)]
pub struct DeferredNow(Option<DateTime<Local>>);
impl<'a> DeferredNow {
    pub(crate) fn new() -> Self {
        Self(None)
    }

    /// Retrieve the timestamp.
    ///
    /// Requires mutability because the first caller will generate the timestamp.
    pub fn now(&'a mut self) -> &'a DateTime<Local> {
        if self.0.is_none() {
            self.0 = Some(Local::now());
        }
        self.0.as_ref().unwrap()
    }
}
