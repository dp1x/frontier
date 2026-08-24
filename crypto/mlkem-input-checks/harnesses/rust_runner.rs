// RustCrypto ml-kem stimulus runner (msn-2026-0001).
// Import path: EncapsulationKey::new_from_slice (fallible, TryKeyInit).
// Deterministic encapsulation via the hazmat API with fixed m.
use ml_kem::{EncapsulationKey, MlKem1024, MlKem512, MlKem768, SharedKey, TryKeyInit};

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

macro_rules! probe_concrete {
    ($set:ty, $ek:expr) => {{
        match EncapsulationKey::<$set>::new_from_slice($ek) {
            Err(_) => "rc=import-rejected|rejected".to_string(),
            Ok(key) => {
                let m = [0x42u8; 32];
                let (_ct, _ss): (_, SharedKey) = key.encapsulate_deterministic(&m.into());
                "rc=0|accepted".to_string()
            }
        }
    }};
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rust_runner <stimuli.tsv> <report.out>");
        std::process::exit(2);
    }
    let data = std::fs::read_to_string(&args[1]).expect("read stimuli");
    let mut out = String::new();
    let mut total = 0usize;
    for line in data.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 5 {
            continue;
        }
        let (family, params, expected, source, ek_hex) =
            (parts[0], parts[1], parts[2], parts[3], parts[4]);
        let Some(ek) = unhex(ek_hex) else {
            continue;
        };
        let verdict = match params {
            "ML-KEM-512" => probe_concrete!(MlKem512, &ek),
            "ML-KEM-768" => probe_concrete!(MlKem768, &ek),
            "ML-KEM-1024" => probe_concrete!(MlKem1024, &ek),
            _ => continue,
        };
        total += 1;
        out.push_str(&format!("{family}|{params}|{expected}|{source}|{verdict}\n"));
    }
    out.push_str(&format!("SUMMARY|total={total}\n"));
    std::fs::write(&args[2], out).expect("write report");
    println!("done: {total} vectors -> {}", args[2]);
}
