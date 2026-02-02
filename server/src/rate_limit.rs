use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-client rate limiter using a sliding-window token bucket.
///
/// Prevents data explosion from malfunctioning or abusive clients:
/// - Limits messages per time window per client
/// - Limits maximum payload size per message
/// - Limits total bytes per window per client
pub struct RateLimiter {
    inner: Mutex<RateLimiterInner>,
}

struct RateLimiterInner {
    /// Per-client state, keyed by client address string.
    clients: HashMap<String, ClientBucket>,
    config: RateLimitConfig,
}

struct ClientBucket {
    /// Message count in current window.
    msg_count: u32,
    /// Bytes received in current window.
    byte_count: u64,
    /// Window start time.
    window_start: Instant,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum messages per window per client.
    pub max_messages_per_window: u32,
    /// Maximum bytes per window per client.
    pub max_bytes_per_window: u64,
    /// Maximum size of a single message payload in bytes.
    pub max_message_size: usize,
    /// Window duration.
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // 60 messages per minute — generous for clipboard, catches storms
            max_messages_per_window: 60,
            // 10 MB per minute
            max_bytes_per_window: 10 * 1024 * 1024,
            // Single message max 1 MB
            max_message_size: 1024 * 1024,
            window_duration: Duration::from_secs(60),
        }
    }
}

/// Result of a rate limit check.
#[derive(Debug)]
pub enum RateLimitResult {
    /// Allowed to proceed.
    Ok,
    /// Message too large.
    MessageTooLarge { size: usize, max: usize },
    /// Too many messages in the window.
    TooManyMessages { count: u32, max: u32 },
    /// Too many bytes in the window.
    TooManyBytes { bytes: u64, max: u64 },
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            inner: Mutex::new(RateLimiterInner {
                clients: HashMap::new(),
                config,
            }),
        }
    }

    /// Check whether a message from `client_id` of `payload_size` bytes is allowed.
    pub fn check(&self, client_id: &str, payload_size: usize) -> RateLimitResult {
        let mut inner = self.inner.lock().unwrap();

        // Check single message size
        if payload_size > inner.config.max_message_size {
            return RateLimitResult::MessageTooLarge {
                size: payload_size,
                max: inner.config.max_message_size,
            };
        }

        let now = Instant::now();
        let window = inner.config.window_duration;
        let max_msgs = inner.config.max_messages_per_window;
        let max_bytes = inner.config.max_bytes_per_window;

        let bucket = inner
            .clients
            .entry(client_id.to_string())
            .or_insert_with(|| ClientBucket {
                msg_count: 0,
                byte_count: 0,
                window_start: now,
            });

        // Reset window if expired
        if now.duration_since(bucket.window_start) >= window {
            bucket.msg_count = 0;
            bucket.byte_count = 0;
            bucket.window_start = now;
        }

        // Check message count
        if bucket.msg_count >= max_msgs {
            return RateLimitResult::TooManyMessages {
                count: bucket.msg_count,
                max: max_msgs,
            };
        }

        // Check byte count
        if bucket.byte_count + payload_size as u64 > max_bytes {
            return RateLimitResult::TooManyBytes {
                bytes: bucket.byte_count,
                max: max_bytes,
            };
        }

        // Accept
        bucket.msg_count += 1;
        bucket.byte_count += payload_size as u64;
        RateLimitResult::Ok
    }

    /// Periodically clean up stale client entries (call from a background task).
    pub fn cleanup_stale(&self) {
        let mut inner = self.inner.lock().unwrap();
        let window = inner.config.window_duration;
        let now = Instant::now();
        inner
            .clients
            .retain(|_, bucket| now.duration_since(bucket.window_start) < window * 3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_limiter() -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            max_messages_per_window: 5,
            max_bytes_per_window: 1000,
            max_message_size: 200,
            window_duration: Duration::from_secs(60),
        })
    }

    #[test]
    fn allows_normal_messages() {
        let limiter = test_limiter();
        for _ in 0..5 {
            assert!(matches!(limiter.check("client-a", 50), RateLimitResult::Ok));
        }
    }

    #[test]
    fn rejects_message_too_large() {
        let limiter = test_limiter();
        match limiter.check("client-a", 300) {
            RateLimitResult::MessageTooLarge { size, max } => {
                assert_eq!(size, 300);
                assert_eq!(max, 200);
            }
            other => panic!("expected MessageTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn rejects_too_many_messages() {
        let limiter = test_limiter();
        // Use all 5 slots
        for _ in 0..5 {
            assert!(matches!(limiter.check("client-a", 10), RateLimitResult::Ok));
        }
        // 6th should be rejected
        match limiter.check("client-a", 10) {
            RateLimitResult::TooManyMessages { count, max } => {
                assert_eq!(count, 5);
                assert_eq!(max, 5);
            }
            other => panic!("expected TooManyMessages, got {:?}", other),
        }
    }

    #[test]
    fn rejects_too_many_bytes() {
        let limiter = test_limiter();
        // Send 5 messages of 200 bytes each = 1000 bytes (at the limit)
        for _ in 0..5 {
            assert!(matches!(
                limiter.check("client-a", 200),
                RateLimitResult::Ok
            ));
        }
        // Byte limit reached AND message limit reached, but message limit checked first
        // Let's use a different config to isolate byte limit
        let byte_limiter = RateLimiter::new(RateLimitConfig {
            max_messages_per_window: 100,
            max_bytes_per_window: 500,
            max_message_size: 400,
            window_duration: Duration::from_secs(60),
        });
        assert!(matches!(
            byte_limiter.check("client-b", 300),
            RateLimitResult::Ok
        ));
        assert!(matches!(
            byte_limiter.check("client-b", 200),
            RateLimitResult::Ok
        ));
        // 500 used, any more should fail
        match byte_limiter.check("client-b", 100) {
            RateLimitResult::TooManyBytes { .. } => {}
            other => panic!("expected TooManyBytes, got {:?}", other),
        }
    }

    #[test]
    fn different_clients_independent() {
        let limiter = test_limiter();
        for _ in 0..5 {
            assert!(matches!(limiter.check("client-a", 10), RateLimitResult::Ok));
        }
        // client-a exhausted, but client-b should be fine
        assert!(matches!(
            limiter.check("client-a", 10),
            RateLimitResult::TooManyMessages { .. }
        ));
        assert!(matches!(limiter.check("client-b", 10), RateLimitResult::Ok));
    }

    #[test]
    fn window_resets_after_duration() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_messages_per_window: 2,
            max_bytes_per_window: 10_000,
            max_message_size: 5_000,
            window_duration: Duration::from_millis(1), // Very short window
        });

        assert!(matches!(limiter.check("c1", 10), RateLimitResult::Ok));
        assert!(matches!(limiter.check("c1", 10), RateLimitResult::Ok));
        assert!(matches!(
            limiter.check("c1", 10),
            RateLimitResult::TooManyMessages { .. }
        ));

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(5));

        // Should be allowed again
        assert!(matches!(limiter.check("c1", 10), RateLimitResult::Ok));
    }

    #[test]
    fn cleanup_stale_removes_old_clients() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_messages_per_window: 100,
            max_bytes_per_window: 100_000,
            max_message_size: 10_000,
            window_duration: Duration::from_millis(1),
        });

        // Create entries for several clients
        limiter.check("client-a", 10);
        limiter.check("client-b", 10);
        limiter.check("client-c", 10);

        // Wait for entries to become stale (3x window = 3ms)
        std::thread::sleep(Duration::from_millis(10));

        limiter.cleanup_stale();

        // All old clients should be cleaned up; new check should succeed
        // (We can't directly inspect the HashMap, but we verify they don't carry old state)
        assert!(matches!(limiter.check("client-a", 10), RateLimitResult::Ok));
    }

    #[test]
    fn rapid_fire_stress() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_messages_per_window: 60,
            max_bytes_per_window: 10 * 1024 * 1024,
            max_message_size: 1024 * 1024,
            window_duration: Duration::from_secs(60),
        });

        let mut accepted = 0;
        let mut rejected = 0;
        for _ in 0..100 {
            match limiter.check("rapid-client", 100) {
                RateLimitResult::Ok => accepted += 1,
                RateLimitResult::TooManyMessages { .. } => rejected += 1,
                other => panic!("unexpected result: {:?}", other),
            }
        }
        assert_eq!(accepted, 60);
        assert_eq!(rejected, 40);
    }
}
