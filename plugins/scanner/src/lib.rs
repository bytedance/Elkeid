pub mod config;
pub mod cronjob;
pub mod detector;
pub mod filter;
pub mod fmonitor;

pub trait ToAgentRecord {
    fn to_record(&self) -> plugins::Record;
}
