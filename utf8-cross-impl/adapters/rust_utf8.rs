use std::io::Read;

fn main() {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf).unwrap();
    match std::str::from_utf8(&buf) {
        Ok(_) => println!("VALID"),
        Err(e) => {
            println!("INVALID");
            eprintln!("{}", e);
        }
    }
}
