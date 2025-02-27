// SPDX-License-Identifier: MIT
//
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::io::BufRead;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use uhid_virt::{Bus, OutputEvent, StreamError, UHIDDevice};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Print debugging information
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// Replay events starting at this timestamp (in milliseconds)
    #[arg(long, default_value_t = 0)]
    start_time: u64,

    /// Replay events stopping at this timestamp (in milliseconds)
    #[arg(long, default_value_t = 0)]
    stop_time: u64,

    /// Replace any pauses in the recording that
    /// exceed N seconds with a 1s pause
    #[arg(long)]
    skip_pauses: Option<u64>,

    /// Path to the hid-recorder recording
    recording: PathBuf,
}

#[derive(Debug)]
struct Event {
    usecs: u64,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct RecordingBuilder {
    name: Option<String>,
    ids: Option<(u16, u16, u16)>,
    rdesc: Option<Vec<u8>>,
    events: Vec<Event>,
}

#[derive(Debug)]
struct Recording {
    name: String,
    ids: (u16, u16, u16),
    rdesc: Vec<u8>,
    events: Vec<Event>,
}

impl Recording {
    fn from_builder(builder: RecordingBuilder) -> Recording {
        Recording {
            name: builder.name.unwrap_or("<missing device name>".into()),
            ids: builder.ids.unwrap_or((0, 0, 0)),
            rdesc: builder.rdesc.unwrap(),
            events: builder.events,
        }
    }
}

/// Decode a length-prefixed string of bytes, e.g.
/// 4 00 01 02 03 04
/// ^ ^------------^
/// |      |
/// |      + bytes in hex
/// +-- length in bytes, decimal
fn decode_length_prefixed_data(str: &str) -> Result<(usize, Vec<u8>)> {
    let Some((length, rest)) = str.split_once(' ') else {
        bail!("Invalid format, expected <length> [byte, byte, ...]");
    };
    let length = length.parse::<usize>()?;
    let bytes = hex::decode(rest.replace(' ', ""))?;

    if length != bytes.len() {
        bail!("Invalid data length: {} expected {}", bytes.len(), length);
    }

    Ok((length, bytes))
}

enum Match {
    Comment,
    Name(String),
    Id((u16, u16, u16)),
    ReportDescriptor(Vec<u8>),
    Event(Event),
    Bpf,
    UnknownPrefix(char),
}

fn parse_line(line: &str) -> Result<Match> {
    if line.is_empty() || line.starts_with("#") {
        return Ok(Match::Comment);
    }
    match line.split_once(' ') {
        Some(("N:", rest)) => Ok(Match::Name(String::from(rest))),
        Some(("I:", rest)) => {
            let ids = rest
                .split(' ')
                .map(|s| u16::from_str_radix(s, 16))
                .collect::<Result<Vec<u16>, _>>()?;
            let ids: [u16; 3] = match ids.try_into() {
                Ok(ids) => ids,
                Err(_) => bail!("Failed to parse all ids"), // ? doesn't work for try_into()
            };
            Ok(Match::Id(ids.into()))
        }
        Some(("R:", rest)) => Ok(Match::ReportDescriptor(
            decode_length_prefixed_data(rest)
                .context("Invalid report descriptor")?
                .1,
        )),
        Some(("E:", rest)) => {
            let Some((timestamp, rest)) = rest.split_once(' ') else {
                bail!("Invalid event format, expected <timestamp> <length>, ...")
            };
            let Some((secs, usecs)) = timestamp.split_once('.') else {
                bail!("Invalid timestamp format")
            };
            let secs = secs
                .parse::<u64>()
                .context(format!("Invalid timestamp string {secs}"))?;
            let usecs = usecs
                .parse::<u64>()
                .context(format!("Invalid timestamp string {usecs}"))?;
            let bytes = decode_length_prefixed_data(rest)
                .context("Invalid event format")?
                .1;
            Ok(Match::Event(Event {
                usecs: secs * 1_000_000 + usecs,
                bytes,
            }))
        }
        Some(("B:", ..)) => Ok(Match::Bpf),
        Some((prefix, _)) => {
            if prefix.len() == 2 && prefix.ends_with(':') {
                Ok(Match::UnknownPrefix(prefix.chars().next().unwrap()))
            } else {
                bail!("invalid or unknown: {line}");
            }
        }
        _ => bail!("invalid or unknown: {line}"),
    }
}

fn parse<I>(lines: I, mut stderr: impl std::io::Write) -> Result<Recording>
where
    I: Iterator<Item = String>,
{
    let mut builder = RecordingBuilder::default();
    let mut warned_prefixes: Vec<char> = vec![];
    for (lineno, line) in lines.enumerate() {
        match parse_line(&line).context(format!("In line {lineno}"))? {
            Match::Comment => {}
            Match::Name(name) => builder.name = Some(name),
            Match::Id(ids) => builder.ids = Some(ids),
            Match::ReportDescriptor(rdesc) => builder.rdesc = Some(rdesc),
            Match::Event(event) => builder.events.push(event),
            Match::Bpf => {}
            Match::UnknownPrefix(prefix) => {
                if !warned_prefixes.iter().any(|w| *w == prefix) {
                    writeln!(
                        stderr,
                        "WARNING: Line {lineno}: Ignoring unknown prefix '{prefix}:' in {line}"
                    )?;
                    warned_prefixes.push(prefix);
                }
            }
        };
    }

    if builder.rdesc.is_none() {
        bail!("Recording is missing the Report Descriptor, cannot continue");
    }
    if builder.name.is_none() {
        writeln!(
            stderr,
            "WARNING: Recording is missing a device name, using built-in default"
        )?;
    }
    if builder.ids.is_none() {
        writeln!(
            stderr,
            "WARNING: Recording is missing a product/vendor IDs, using built-in defaults"
        )?;
    }

    Ok(Recording::from_builder(builder))
}

fn hid_replay() -> Result<()> {
    let cli = Cli::parse();

    let f = std::fs::File::open(cli.recording)?;
    let lines = std::io::BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .map(|l| String::from(l.trim()));
    let mut recording = parse(lines, &mut std::io::stderr())?;

    println!(
        "Device {:04X}:{:04X}:{:04X} - {}",
        recording.ids.0, recording.ids.1, recording.ids.2, recording.name
    );

    if cli.start_time > 0 || cli.stop_time > 0 {
        recording.events = recording
            .events
            .into_iter()
            .skip_while(|e| e.usecs < cli.start_time * 1000)
            .take_while(|e| cli.stop_time == 0 || e.usecs < cli.stop_time * 1000)
            .collect();
    }

    let recording = recording;
    if let Some(last_event) = recording.events.last() {
        let secs = (last_event.usecs - cli.start_time * 1000) / 1_000_000;
        println!(
            "Recording is {secs}s long ({} HID reports).",
            recording.events.len()
        );
    } else {
        println!("This recording has no events!");
    }

    let bus = match recording.ids.0 {
        1 => Bus::PCI,
        2 => Bus::ISAPNP,
        3 => Bus::USB,
        4 => Bus::HIL,
        5 => Bus::BLUETOOTH,
        6 => Bus::VIRTUAL,
        16 => Bus::ISA,
        17 => Bus::I8042,
        18 => Bus::XTKBD,
        19 => Bus::RS232,
        20 => Bus::GAMEPORT,
        21 => Bus::PARPORT,
        22 => Bus::AMIGA,
        23 => Bus::ADB,
        24 => Bus::I2C,
        25 => Bus::HOST,
        26 => Bus::GSC,
        27 => Bus::ATARI,
        28 => Bus::SPI,
        29 => Bus::RMI,
        30 => Bus::CEC,
        31 => Bus::INTEL_ISHTP,
        _ => bail!("Unknown bus type: {}", recording.ids.0),
    };

    let create_params = uhid_virt::CreateParams {
        name: format!("hid-replay {}", recording.name),
        phys: "".to_string(),
        uniq: "".to_string(),
        bus,
        vendor: recording.ids.1 as u32,
        product: recording.ids.2 as u32,
        version: 0,
        country: 0,
        rd_data: recording.rdesc,
    };

    let mut uhid_device = UHIDDevice::create(create_params)?;

    let uhid_sysfs = PathBuf::from("/sys/devices/virtual/misc/uhid/");
    // Devices use bus/vid/pid like this: 0003:056A:0357.0049 with the last component
    // being an incremental (and thus not predictable) number
    let globname = format!(
        "{:04X}:{:04X}:{:04X}.*",
        recording.ids.0, recording.ids.1, recording.ids.2
    );
    let globstr = uhid_sysfs.join(globname);
    let globstr = globstr.to_string_lossy();

    loop {
        // We might have a GetFeature request waiting which we'll just
        // reply to with EIO, that's good enough for what we do here.
        // uhid_virt doesn't expose the fd though so we can only
        // try to read, fail, and continue, no polling.
        match uhid_device.read() {
            Ok(OutputEvent::GetReport { id, .. }) => {
                uhid_device.write_get_report_reply(id, nix::errno::Errno::EIO as u16, vec![])?;
            }
            Ok(OutputEvent::SetReport { id, .. }) => {
                uhid_device.write_set_report_reply(id, nix::errno::Errno::EIO as u16)?;
            }
            Ok(_) => {}
            Err(StreamError::Io(e)) => match e.kind() {
                std::io::ErrorKind::WouldBlock => {}
                _ => bail!(e),
            },
            Err(StreamError::UnknownEventType(e)) => bail!("Unknown error {e}"),
        }

        // Check if there's a `hidraw` directory inside our just-created
        // uhid sysfs path. If not we have the uhid device but not yet
        // the hidraw device. This means the kernel is still sending us
        // GetReports that we have to process.
        //
        // We may have multiple devices with the same bus/vid/pid so we check
        // for all of them to have a hidraw directory. In the worst case we may
        // have to wait for a different device to initialize but let's consider
        // that a bit niche.
        let mut have_elements = false;
        if glob::glob(&globstr)
            .context("Failed to read glob pattern")?
            .all(|e| {
                have_elements = true;
                e.is_ok() && e.unwrap().join("hidraw").exists()
            })
            && have_elements
        {
            break;
        };
        std::thread::sleep(Duration::from_millis(10));
    }

    // hidraw nodes exist now, let's print them and the associated evdev nodes
    // too.
    //
    // If there's a device with the same VID/PID we'll print that too, unfortunately
    // we can't get the hidraw path from the uhid device we just created.
    // Niche enough to not worry about.
    let hidraw_glob = format!("{globstr}/hidraw/hidraw*");
    glob::glob(&hidraw_glob)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .for_each(|path| {
            println!("/dev/{}:", path.file_name().unwrap().to_string_lossy());

            let evdev_glob = format!("{}/device/input/input*/event*", path.to_string_lossy());
            glob::glob(&evdev_glob)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .for_each(|node| {
                    let name: PathBuf = node.join("device").join("name");
                    let node = node.file_name().unwrap().to_string_lossy();
                    let name = std::fs::read_to_string(name).unwrap();
                    let name = name.trim();
                    println!("- /dev/input/{node}: \"{name}\"");
                });
        });

    let mut pos = 0i8;
    let mut direction = 1i8;
    loop {
        print!("Hit enter to start replaying the events");
        std::io::stdout().flush().unwrap();
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;
        // we need some loop condition, otherwise rust detects the
        // loop can never enter and throws away our uhid device. weird.
        if buffer.trim() == "quit" {
            break;
        }
        let start_time = Instant::now();
        // If we skip over pauses, all events after pauses need to be offset
        // by the pause.
        let mut offset = Duration::from_secs(0);
        for e in &recording.events {
            let current_time = Instant::now();
            // actual time passed since we started
            let elapsed = current_time.duration_since(start_time);
            // what our recording said
            let target_time = Duration::from_micros(e.usecs) - offset;
            if target_time > elapsed {
                let mut interval = target_time - elapsed;
                match cli.skip_pauses {
                    None => {}
                    Some(skip) => {
                        if interval > Duration::from_secs(skip) {
                            let skip_time = Duration::from_secs(1);
                            offset += interval - skip_time;
                            let note = format!(
                                "***** Skipping over pause of {}s *****",
                                interval.as_secs()
                            );
                            print!("\r{:^50}", note);
                            std::io::stdout().flush().unwrap();
                            interval = skip_time;
                        }
                    }
                }
                if interval < Duration::from_secs(2) {
                    std::thread::sleep(interval);
                } else {
                    while interval > Duration::from_secs(1) {
                        let note = format!("***** Sleeping for {}s *****", interval.as_secs());
                        print!("\r{:^50}", note);
                        std::io::stdout().flush().unwrap();
                        std::thread::sleep(std::cmp::min(interval, Duration::from_secs(1)));

                        let elapsed = Instant::now().duration_since(start_time);
                        interval = target_time - elapsed;
                    }
                    std::thread::sleep(interval);
                }
            }
            if cli.verbose {
                // Note: printing the event's original timestamp, not the current timestamp
                // so it's easier to match the --verbose output with the recording.
                println!(
                    "\rE: {:06}.{:06} {} {}",
                    e.usecs / 1000000,
                    e.usecs % 1000000,
                    e.bytes.len(),
                    e.bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<String>>()
                        .join(" ")
                );
            } else {
                print!("\r{1:0$}*{1:2$}", pos as usize, " ", 50 - pos as usize);
                pos += direction;
                if pos % 49 == 0 {
                    direction *= -1;
                }
                std::io::stdout().flush().unwrap();
            }
            uhid_device.write(&e.bytes)?;
        }
        print!("\r{:50}\r", " ");
        std::io::stdout().flush().unwrap();
    }

    Ok(())
}

fn main() -> ExitCode {
    let rc = hid_replay();
    match rc {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_name() {
        let mut stderr = Vec::new();
        let lines = vec!["I: 1 2 3", "R: 3 02 03 04"]
            .into_iter()
            .map(String::from);
        let recording = parse(lines, &mut stderr);
        assert!(recording.is_ok());
        let recording = recording.unwrap();
        assert_eq!(recording.name, "<missing device name>");
        let stderr = String::from_utf8(stderr).unwrap();
        assert_eq!(
            stderr.trim(),
            "WARNING: Recording is missing a device name, using built-in default"
        )
    }

    #[test]
    fn test_missing_id() {
        let mut stderr = Vec::new();
        let lines = vec!["N: some name", "R: 3 02 03 04"]
            .into_iter()
            .map(String::from);
        let recording = parse(lines, &mut stderr);
        assert!(recording.is_ok());
        let recording = recording.unwrap();
        assert_eq!(recording.ids, (0, 0, 0));
        let stderr = String::from_utf8(stderr).unwrap();
        assert_eq!(
            stderr.trim(),
            "WARNING: Recording is missing a product/vendor IDs, using built-in defaults"
        );
    }

    #[test]
    fn test_fail_on_missing_rdesc() {
        let mut stderr = Vec::new();
        let lines = vec!["N: some name", "I: 1 2 4"]
            .into_iter()
            .map(String::from);
        let recording = parse(lines, &mut stderr);
        assert!(recording.is_err());
    }

    #[test]
    fn test_parse_unknown_prefix() {
        let mut stderr = Vec::new();
        let lines = vec!["N: some name", "I: 1 2 3", "R: 3 02 03 04", "X: blah"]
            .into_iter()
            .map(String::from);
        let recording = parse(lines, &mut stderr);
        assert!(recording.is_ok());
        let stderr = String::from_utf8(stderr).unwrap();
        assert_eq!(
            stderr.trim(),
            "WARNING: Line 3: Ignoring unknown prefix 'X:' in X: blah"
        );
    }

    #[test]
    fn test_fail_invalid_prefix() {
        let mut stderr = Vec::new();
        let lines = vec!["N: some name", "I: 1 2 3", "R: 3 02 03 04", "xxx: blah"]
            .into_iter()
            .map(String::from);
        let recording = parse(lines, &mut stderr);
        assert!(recording.is_err());
    }

    #[test]
    fn test_ids() {
        assert!(parse_line("I: ").is_err());
        assert!(parse_line("I: 0").is_err());
        assert!(parse_line("I: 0 0").is_err());
        assert!(parse_line("I: 0 0 0 0").is_err());

        let result = parse_line("I: a b c").unwrap();
        assert!(matches!(result, Match::Id((0xa, 0xb, 0xc))));
        let result = parse_line("I: 0 1 2").unwrap();
        assert!(matches!(result, Match::Id((0, 1, 2))));
    }

    #[test]
    fn test_length_prefixed_data_invalid() {
        let result = decode_length_prefixed_data("0");
        assert!(result.is_err());

        let result = decode_length_prefixed_data("0 00");
        assert!(result.is_err());

        let result = decode_length_prefixed_data("1;01");
        assert!(result.is_err());

        let result = decode_length_prefixed_data("1 0001");
        assert!(result.is_err());

        let result = decode_length_prefixed_data("1 0x0001");
        assert!(result.is_err());

        let result = decode_length_prefixed_data("1 01 02");
        assert!(result.is_err());

        let result = decode_length_prefixed_data("3 01 02");
        assert!(result.is_err());
    }

    #[test]
    fn test_length_prefixed_data_valid() {
        let result = decode_length_prefixed_data("1 00");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (1, vec![0]));

        let result = decode_length_prefixed_data("1 01");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (1, vec![1]));

        let result = decode_length_prefixed_data("4 01 bc AF 10");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (4, vec![0x01, 0xbc, 0xaf, 0x10]));
    }
}
