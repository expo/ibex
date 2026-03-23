use std::sync::{Mutex, MutexGuard};

/// Recover the inner value from poisoned mutexes so one panic does not
/// permanently take down the rest of the process.
pub fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
