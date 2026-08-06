//! Singleflight - Query Deduplication
//!
//! Prevents duplicate concurrent queries to upstream (thundering herd prevention)

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use std::task::{Context, Poll};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Result of a singleflight query
#[derive(Clone)]
pub enum FlightResult<T> {
    /// This query was the leader (first to arrive)
    Leader(T),
    /// This query waited for the leader's result
    Follower(T),
}

struct Flight<T> {
    result: Option<Arc<T>>,
    notify: Arc<Notify>,
    waiters: usize,
}

/// Singleflight coordinator for query deduplication
pub struct Singleflight<T> {
    flights: Arc<Mutex<HashMap<String, Flight<T>>>>,
}

impl<T: Clone + Send + Sync + 'static> Singleflight<T> {
    /// Create new singleflight coordinator
    pub fn new() -> Self {
        Self {
            flights: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Execute query with deduplication
    /// 
    /// If another query with the same key is in-flight, this will wait
    /// for its result instead of executing the closure.
    pub async fn execute<F, Fut>(&self, key: String, f: F) -> FlightResult<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        let notify: Arc<Notify>;
        let is_leader: bool;

        // Check if query is already in-flight
        {
            let mut flights = self.flights.lock().await;
            
            if let Some(flight) = flights.get_mut(&key) {
                // Query in-flight, wait for it
                flight.waiters += 1;
                notify = flight.notify.clone();
                is_leader = false;
            } else {
                // We're the leader, create new flight
                let new_notify = Arc::new(Notify::new());
                notify = new_notify.clone();
                
                flights.insert(key.clone(), Flight {
                    result: None,
                    notify: new_notify,
                    waiters: 0,
                });
                is_leader = true;
            }
        }

        if is_leader {
            // Execute the query
            let result = f().await;
            let result_arc = Arc::new(result);

            // Store result and notify waiters
            {
                let mut flights = self.flights.lock().await;
                if let Some(flight) = flights.get_mut(&key) {
                    flight.result = Some(result_arc.clone());
                    flight.notify.notify_waiters();
                }
            }

            // Clean up after a brief delay to allow followers to grab result
            let flights_clone = self.flights.clone();
            let key_clone = key.clone();
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let mut flights = flights_clone.lock().await;
                flights.remove(&key_clone);
            });

            FlightResult::Leader(Arc::try_unwrap(result_arc).unwrap_or_else(|arc| (*arc).clone()))
        } else {
            // Wait for leader's result
            notify.notified().await;

            let result = {
                let flights = self.flights.lock().await;
                flights
                    .get(&key)
                    .and_then(|f| f.result.clone())
                    .expect("Result should be available after notification")
            };

            FlightResult::Follower((*result).clone())
        }
    }

    /// Get current number of in-flight queries
    pub async fn in_flight_count(&self) -> usize {
        self.flights.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_singleflight_dedup() {
        let sf = Singleflight::<String>::new();
        let counter = Arc::new(AtomicU32::new(0));

        // Launch 10 concurrent queries for same key
        let mut handles = vec![];
        for _ in 0..10 {
            let sf_clone = Singleflight {
                flights: sf.flights.clone(),
            };
            let counter_clone = counter.clone();

            let handle = tokio::spawn(async move {
                sf_clone
                    .execute("test.com".to_string(), || async move {
                        counter_clone.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        "result".to_string()
                    })
                    .await
            });
            handles.push(handle);
        }

        // Wait for all
        for handle in handles {
            let result = handle.await.unwrap();
            match result {
                FlightResult::Leader(s) | FlightResult::Follower(s) => {
                    assert_eq!(s, "result");
                }
            }
        }

        // Only executed once!
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_different_keys() {
        let sf = Singleflight::<String>::new();
        let counter = Arc::new(AtomicU32::new(0));

        // Different keys should execute separately
        let mut handles = vec![];
        for i in 0..5 {
            let sf_clone = Singleflight {
                flights: sf.flights.clone(),
            };
            let counter_clone = counter.clone();

            let handle = tokio::spawn(async move {
                sf_clone
                    .execute(format!("test{}.com", i), move || async move {
                        counter_clone.fetch_add(1, Ordering::Relaxed);
                        format!("result{}", i)
                    })
                    .await
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        // All 5 executed
        assert_eq!(counter.load(Ordering::Relaxed), 5);
    }
}
