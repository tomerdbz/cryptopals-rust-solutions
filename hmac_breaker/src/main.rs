use clap::{AppSettings, Clap};
use hex;
use std::collections::HashMap;
use std::io::Write;
use std::str::FromStr;
use std::time::Instant;

//// Gets the correct HMAC for the specified blob
#[derive(Clap)]
#[clap(version = "1.0", author = "tomerdbz")]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    #[clap(short)]
    blob: String,
    #[clap(short)]
    server_delay: ServerDelay,
}

#[derive(Copy, Clone)]
pub enum ServerDelay {
    Tiny = 50,
    Small = 1,
}

impl FromStr for ServerDelay {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Tiny" => Ok(ServerDelay::Tiny),
            "Small" => Ok(ServerDelay::Small),
            _ => Err("no match"),
        }
    }
}

fn main() {
    let opts: Opts = Opts::parse();
    let mut hmac: [u8; 20] = [0; 20];
    for i in 0..20 {
        let mut iteration_result: HashMap<u8, std::time::Duration> = HashMap::new();
        for b in 0..=u8::MAX {
            iteration_result.insert(b, std::time::Duration::new(0, 0));
        }
        for _ in 0..opts.server_delay as usize {
            for b in 0..=u8::MAX {
                hmac[i] = b;
                let start = Instant::now();
                reqwest::blocking::get(format!(
                    "http://localhost:5000/test?file={}&signature={}",
                    opts.blob,
                    hex::encode(hmac)
                ))
                .unwrap();
                *iteration_result.get_mut(&b).unwrap() += start.elapsed();
            }
        }
        let byte = iteration_result
            .iter()
            .max_by(|a, b| a.1.cmp(&b.1))
            .map(|(k, _v)| k)
            .unwrap();
        print!("{:x}", byte);
        std::io::stdout().flush();
        hmac[i] = *byte;
    }
    let response = reqwest::blocking::get(format!(
        "http://localhost:5000/test?file={}&signature={}",
        opts.blob,
        hex::encode(hmac)
    ))
    .unwrap();

    println!(
        "\nhmac verification status: {}",
        response.status().is_success()
    );
}
