use std::sync::{
  atomic::{AtomicUsize, Ordering},
  Arc,
};

#[derive(Debug, Default)]
/// Connection counter inner that is an increment-only counter
/// For performance, we do not care about the memory ordering, which means values are sometimes inconsistent (like being negative value).
struct CounterInner {
  /// total number of incoming connections
  cnt_in: AtomicUsize,
  /// total number of served connections
  cnt_out: AtomicUsize,
}

impl CounterInner {
  /// output difference between cnt_in and cnt_out as current in-flight connection count
  fn get_current(&self) -> isize {
    self.cnt_in.load(Ordering::Relaxed) as isize - self.cnt_out.load(Ordering::Relaxed) as isize
  }
  /// increment cnt_in and output current in-flight connection count
  fn increment(&self) -> isize {
    let total_in = self.cnt_in.fetch_add(1, Ordering::Relaxed) as isize;
    total_in + 1 - self.cnt_out.load(Ordering::Relaxed) as isize
  }
  /// increment cnt_out and output current in-flight connection count
  fn decrement(&self) -> isize {
    let total_out = self.cnt_out.fetch_add(1, Ordering::Relaxed) as isize;
    self.cnt_in.load(Ordering::Relaxed) as isize - total_out - 1
  }
}

#[derive(Debug, Clone, Default)]
/// Counter for serving requests
pub struct RequestCount(Arc<CounterInner>);

impl RequestCount {
  pub fn current(&self) -> isize {
    self.0.get_current()
  }

  pub fn increment(&self) -> isize {
    self.0.increment()
  }

  pub fn decrement(&self) -> isize {
    self.0.decrement()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_counter() {
    let counter = RequestCount::default();
    assert_eq!(counter.current(), 0);
    assert_eq!(counter.increment(), 1);
    assert_eq!(counter.current(), 1);
    assert_eq!(counter.increment(), 2);
    assert_eq!(counter.current(), 2);
    assert_eq!(counter.decrement(), 1);
    assert_eq!(counter.current(), 1);
    assert_eq!(counter.decrement(), 0);
    assert_eq!(counter.current(), 0);
    assert_eq!(counter.decrement(), -1);
    assert_eq!(counter.current(), -1);
    assert_eq!(counter.increment(), 0);
    assert_eq!(counter.current(), 0);
  }
}
