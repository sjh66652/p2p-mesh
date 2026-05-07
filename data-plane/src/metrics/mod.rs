//! Network quality metrics module.
//!
//! Measures and tracks:
//! - RTT (round-trip time) via PING/PONG messages
//! - Packet loss rate via sequence number tracking
//! - Estimated bandwidth via bytes-per-second sampling
//!
//! Provides a unified quality score for path comparison.

use std::time::{Duration, Instant};

/// Network quality metrics for a path.
#[derive(Debug, Clone)]
pub struct PathMetrics {
    /// Average RTT in microseconds (smoothed via EWMA)
    pub rtt_avg: Duration,
    /// Minimum observed RTT
    pub rtt_min: Duration,
    /// Maximum observed RTT
    pub rtt_max: Duration,
    /// Number of RTT samples collected
    pub rtt_samples: u64,
    /// Packet loss rate (0.0 = no loss, 1.0 = all lost)
    pub loss_rate: f64,
    /// Packets sent (for loss calculation)
    pub packets_sent: u64,
    /// Packets acknowledged
    pub packets_acked: u64,
    /// Estimated bandwidth in bytes per second (EWMA)
    pub bandwidth_bps: u64,
    /// Last bandwidth sample timestamp
    last_bw_sample: Instant,
    /// Bytes received in current bandwidth window
    bytes_in_window: u64,
    /// EWMA smoothing factor (0.0-1.0, lower = smoother)
    alpha: f64,
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self {
            rtt_avg: Duration::from_secs(0),
            rtt_min: Duration::from_secs(10), // unreasonable large for min
            rtt_max: Duration::from_secs(0),
            rtt_samples: 0,
            loss_rate: 0.0,
            packets_sent: 0,
            packets_acked: 0,
            bandwidth_bps: 0,
            last_bw_sample: Instant::now(),
            bytes_in_window: 0,
            alpha: 0.125, // EWMA smoothing factor
        }
    }
}

impl PathMetrics {
    /// Record a new RTT sample. Uses EWMA for smoothing.
    pub fn record_rtt(&mut self, rtt: Duration) {
        self.rtt_samples += 1;

        if self.rtt_samples == 1 {
            self.rtt_avg = rtt;
            self.rtt_min = rtt;
            self.rtt_max = rtt;
        } else {
            // EWMA: avg = alpha * sample + (1-alpha) * old_avg
            let new_avg_micros = (self.alpha * rtt.as_micros() as f64
                + (1.0 - self.alpha) * self.rtt_avg.as_micros() as f64)
                as u128;
            self.rtt_avg = Duration::from_micros(new_avg_micros as u64);
            self.rtt_min = self.rtt_min.min(rtt);
            self.rtt_max = self.rtt_max.max(rtt);
        }
    }

    /// Record a sent packet.
    pub fn record_send(&mut self) {
        self.packets_sent += 1;
    }

    /// Record an acknowledged packet.
    pub fn record_ack(&mut self) {
        self.packets_acked += 1;
        self.update_loss_rate();
    }

    /// Record bytes received for bandwidth estimation.
    pub fn record_bytes(&mut self, bytes: u64) {
        self.bytes_in_window += bytes;

        let elapsed = self.last_bw_sample.elapsed();
        if elapsed >= Duration::from_secs(1) {
            let current_bps = (self.bytes_in_window as f64 / elapsed.as_secs_f64()) as u64;

            if self.bandwidth_bps == 0 {
                self.bandwidth_bps = current_bps;
            } else {
                // EWMA bandwidth
                self.bandwidth_bps = (self.alpha * current_bps as f64
                    + (1.0 - self.alpha) * self.bandwidth_bps as f64)
                    as u64;
            }

            self.bytes_in_window = 0;
            self.last_bw_sample = Instant::now();
        }
    }

    /// Bulk update metrics from external measurements.
    pub fn update(&mut self, rtt: Duration, loss_rate: f64, bandwidth: u64) {
        self.record_rtt(rtt);
        self.loss_rate = loss_rate;
        if bandwidth > 0 {
            if self.bandwidth_bps == 0 {
                self.bandwidth_bps = bandwidth;
            } else {
                self.bandwidth_bps = (self.alpha * bandwidth as f64
                    + (1.0 - self.alpha) * self.bandwidth_bps as f64)
                    as u64;
            }
        }
    }

    /// Update the packet loss rate.
    fn update_loss_rate(&mut self) {
        if self.packets_sent == 0 {
            self.loss_rate = 0.0;
        } else {
            self.loss_rate = 1.0 - (self.packets_acked as f64 / self.packets_sent as f64);
        }
    }

    /// Compute a unified quality score (0.0 = worst, 1.0 = best).
    /// Higher score means better quality.
    pub fn score(&self) -> QualityScore {
        // Normalize RTT to 0-1 scale (0ms=1.0, 500ms+=0.0)
        let rtt_score = if self.rtt_samples == 0 {
            0.5 // unknown = neutral
        } else {
            let rtt_ms = self.rtt_avg.as_millis() as f64;
            (1.0 - (rtt_ms / 500.0)).clamp(0.0, 1.0)
        };

        // Loss score (0% loss = 1.0, 100% loss = 0.0)
        let loss_score = 1.0 - self.loss_rate;

        // Bandwidth score (normalized to 1 Gbps max)
        let bw_score = ((self.bandwidth_bps as f64) / (1_000_000_000.0)).min(1.0);
        // Weighted composite score
        let score = rtt_score * 0.5 + loss_score * 0.3 + bw_score * 0.2;

        QualityScore {
            total: score,
            rtt: rtt_score,
            loss: loss_score,
            bandwidth: bw_score,
        }
    }
}

/// Quality score breakdown for a path.
#[derive(Debug, Clone)]
pub struct QualityScore {
    /// Overall quality (0.0-1.0)
    pub total: f64,
    /// RTT score
    pub rtt: f64,
    /// Loss rate score
    pub loss: f64,
    /// Bandwidth score
    pub bandwidth: f64,
}
