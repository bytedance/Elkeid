use crate::deferred_now::DeferredNow;
use crate::writers::log_writer::LogWriter;
use std::cell::RefCell;
use std::ffi::OsString;
use std::io::Error as IoError;
use std::io::Result as IoResult;
use std::io::{BufWriter, ErrorKind, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::sync::Mutex;

/// Syslog Facility.
///
/// See [RFC 5424](https://datatracker.ietf.org/doc/rfc5424).
#[derive(Copy, Clone, Debug)]
pub enum SyslogFacility {
    /// kernel messages.
    Kernel = 0 << 3,
    /// user-level messages.
    UserLevel = 1 << 3,
    /// mail system.
    MailSystem = 2 << 3,
    /// system daemons.
    SystemDaemons = 3 << 3,
    /// security/authorization messages.
    Authorization = 4 << 3,
    /// messages generated internally by syslogd.
    SyslogD = 5 << 3,
    /// line printer subsystem.
    LinePrinter = 6 << 3,
    /// network news subsystem.
    News = 7 << 3,
    /// UUCP subsystem.
    Uucp = 8 << 3,
    /// clock daemon.
    Clock = 9 << 3,
    /// security/authorization messages.
    Authorization2 = 10 << 3,
    /// FTP daemon.
    Ftp = 11 << 3,
    /// NTP subsystem.
    Ntp = 12 << 3,
    /// log audit.
    LogAudit = 13 << 3,
    /// log alert.
    LogAlert = 14 << 3,
    /// clock daemon (note 2).
    Clock2 = 15 << 3,
    /// local use 0  (local0).
    LocalUse0 = 16 << 3,
    /// local use 1  (local1).
    LocalUse1 = 17 << 3,
    /// local use 2  (local2).
    LocalUse2 = 18 << 3,
    /// local use 3  (local3).
    LocalUse3 = 19 << 3,
    /// local use 4  (local4).
    LocalUse4 = 20 << 3,
    /// local use 5  (local5).
    LocalUse5 = 21 << 3,
    /// local use 6  (local6).
    LocalUse6 = 22 << 3,
    /// local use 7  (local7).
    LocalUse7 = 23 << 3,
}

/// `SyslogConnector`'s severity.
///
/// See [RFC 5424](https://datatracker.ietf.org/doc/rfc5424).
#[derive(Debug)]
pub enum SyslogSeverity {
    /// System is unusable.
    Emergency = 0,
    /// Action must be taken immediately.
    Alert = 1,
    /// Critical conditions.
    Critical = 2,
    /// Error conditions.
    Error = 3,
    /// Warning conditions
    Warning = 4,
    /// Normal but significant condition
    Notice = 5,
    /// Informational messages.
    Info = 6,
    /// Debug-level messages.
    Debug = 7,
}

/// Signature for a custom mapping function that maps the rust log levels to
/// values of the syslog Severity.
pub type LevelToSyslogSeverity = fn(level: log::Level) -> SyslogSeverity;

fn default_mapping(level: log::Level) -> SyslogSeverity {
    match level {
        log::Level::Error => SyslogSeverity::Error,
        log::Level::Warn => SyslogSeverity::Warning,
        log::Level::Info => SyslogSeverity::Info,
        log::Level::Debug | log::Level::Trace => SyslogSeverity::Debug,
    }
}

/// An experimental configurable `LogWriter` implementation that writes log messages to the syslog
/// (see [RFC 5424](https://datatracker.ietf.org/doc/rfc5424)).
///
/// Only available with optional crate feature `syslog_writer`.
///
/// For using the `SyslogWriter`, you need to know how the syslog is managed on your system,  
/// how you can access it and with which protocol you can write to it,
/// so that you can choose a variant of the `SyslogConnector` that fits to your environment.
///
/// See the [module description](index.html) for guidance how to use additional log writers.
pub struct SyslogWriter {
    hostname: OsString,
    process: String,
    pid: u32,
    facility: SyslogFacility,
    message_id: String,
    determine_severity: LevelToSyslogSeverity,
    syslog: Mutex<RefCell<SyslogConnector>>,
    max_log_level: log::LevelFilter,
}
impl SyslogWriter {
    /// Returns a configured boxed instance.
    ///
    /// ## Parameters
    ///
    /// `facility`: An value representing a valid syslog facility value according to RFC 5424.
    ///
    /// `determine_severity`: (optional) A function that maps the rust log levels
    /// to the syslog severities. If None is given, a trivial default mapping is used, which
    /// should be good enough in most cases.
    ///
    /// `message_id`: The value being used as syslog's MSGID, which
    /// should identify the type of message. The value itself
    /// is a string without further semantics. It is intended for filtering
    /// messages on a relay or collector.
    ///
    /// `syslog`: A [`SyslogConnector`](enum.SyslogConnector.html).
    ///
    /// # Errors
    ///
    /// `std::io::Error`
    pub fn try_new(
        facility: SyslogFacility,
        determine_severity: Option<LevelToSyslogSeverity>,
        max_log_level: log::LevelFilter,
        message_id: String,
        syslog: SyslogConnector,
    ) -> IoResult<Box<Self>> {
        Ok(Box::new(Self {
            hostname: hostname::get().unwrap_or_else(|_| OsString::from("<unknown_hostname>")),
            process: std::env::args()
                .next()
                .ok_or_else(|| IoError::new(ErrorKind::Other, "<no progname>".to_owned()))?,
            pid: std::process::id(),
            facility,
            max_log_level,
            message_id,
            determine_severity: determine_severity.unwrap_or_else(|| default_mapping),
            syslog: Mutex::new(RefCell::new(syslog)),
        }))
    }
}

impl LogWriter for SyslogWriter {
    fn write(&self, now: &mut DeferredNow, record: &log::Record) -> IoResult<()> {
        let mr_syslog = self.syslog.lock().unwrap();
        let mut syslog = mr_syslog.borrow_mut();

        let severity = (self.determine_severity)(record.level());
        write!(
            syslog,
            "{}",
            format!(
                "<{}>1 {} {:?} {} {} {} - {}\n",
                self.facility as u8 | severity as u8,
                now.now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Micros, false),
                self.hostname,
                self.process,
                self.pid,
                self.message_id,
                &record.args()
            )
        )
    }

    fn flush(&self) -> IoResult<()> {
        let mr_syslog = self.syslog.lock().unwrap();
        let mut syslog = mr_syslog.borrow_mut();
        syslog.flush()?;
        Ok(())
    }

    fn max_log_level(&self) -> log::LevelFilter {
        self.max_log_level
    }
}

/// Helper struct that connects to the syslog and implements Write.
///
/// Is used in [`SyslogWriter::try_new`](struct.SyslogWriter.html#method.try_new).
///
/// ## Example
///
/// ```rust,no_run
///     use flexi_logger::writers::SyslogConnector;
///    let syslog_connector = SyslogConnector::try_tcp("localhost:7777").unwrap();
/// ```
///
#[derive(Debug)]
pub enum SyslogConnector {
    /// Sends log lines to the syslog via a
    /// [UnixStream](https://doc.rust-lang.org/std/os/unix/net/struct.UnixStream.html).
    ///
    /// Is only available on linux.
    #[cfg(target_os = "linux")]
    Stream(BufWriter<std::os::unix::net::UnixStream>),

    /// Sends log lines to the syslog via a
    /// [UnixDatagram](https://doc.rust-lang.org/std/os/unix/net/struct.UnixDatagram.html).
    ///
    /// Is only available on linux.
    #[cfg(target_os = "linux")]
    Datagram(std::os::unix::net::UnixDatagram),

    /// Sends log lines to the syslog via UDP.
    ///
    /// UDP is fragile and thus discouraged except for local communication.
    Udp(UdpSocket),

    /// Sends log lines to the syslog via TCP.
    Tcp(BufWriter<TcpStream>),
}
impl SyslogConnector {
    /// Returns a `SyslogConnector::Datagram` to the specified path.
    ///
    /// Is only available on linux.
    #[cfg(target_os = "linux")]
    pub fn try_datagram<P: AsRef<Path>>(path: P) -> IoResult<SyslogConnector> {
        let ud = std::os::unix::net::UnixDatagram::unbound()?;
        ud.connect(&path)?;
        Ok(SyslogConnector::Datagram(ud))
    }

    /// Returns a `SyslogConnector::Stream` to the specified path.
    ///
    /// Is only available on linux.
    #[cfg(target_os = "linux")]
    pub fn try_stream<P: AsRef<Path>>(path: P) -> IoResult<SyslogConnector> {
        Ok(SyslogConnector::Stream(BufWriter::new(
            std::os::unix::net::UnixStream::connect(path)?,
        )))
    }

    /// Returns a `SyslogConnector` which sends the log lines via TCP to the specified address.
    ///
    /// # Errors
    ///
    /// `std::io::Error` if opening the stream fails.
    pub fn try_tcp<T: ToSocketAddrs>(server: T) -> IoResult<Self> {
        Ok(Self::Tcp(BufWriter::new(TcpStream::connect(server)?)))
    }

    /// Returns a `SyslogConnector` which sends log via the fragile UDP protocol from local to server.
    ///
    /// # Errors
    ///
    /// `std::io::Error` if opening the stream fails.
    pub fn try_udp<T: ToSocketAddrs>(local: T, server: T) -> IoResult<Self> {
        let socket = UdpSocket::bind(local)?;
        socket.connect(server)?;
        Ok(Self::Udp(socket))
    }
}

impl Write for SyslogConnector {
    fn write(&mut self, message: &[u8]) -> IoResult<usize> {
        // eprintln!(
        //     "syslog: got message \"{}\" ",
        //     String::from_utf8_lossy(message)
        // );
        match *self {
            #[cfg(target_os = "linux")]
            Self::Datagram(ref ud) => {
                // todo: reconnect of conn is broken
                ud.send(&message[..])
            }
            #[cfg(target_os = "linux")]
            Self::Stream(ref mut w) => {
                // todo: reconnect of conn is broken
                w.write(&message[..])
                    .and_then(|sz| w.write_all(&[0; 1]).map(|_| sz))
            }
            Self::Tcp(ref mut w) => {
                // todo: reconnect of conn is broken
                w.write(&message[..])
            }
            Self::Udp(ref socket) => {
                // ??
                socket.send(&message[..])
            }
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        match *self {
            #[cfg(target_os = "linux")]
            Self::Datagram(_) => Ok(()),

            #[cfg(target_os = "linux")]
            Self::Stream(ref mut w) => w.flush(),

            Self::Udp(_) => Ok(()),

            Self::Tcp(ref mut w) => w.flush(),
        }
    }
}
