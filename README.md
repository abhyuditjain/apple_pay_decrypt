# Apple Pay Decrypt

A Rust library for decrypting Apple Pay payment tokens.

## Installation

Add this crate to your `Cargo.toml`:

```toml
[dependencies]
apple-pay-decrypt = "0.1.0"
```

## Example

```rust
use std::{error::Error, fs};
use apple_pay_decrypt::EncryptedToken;

fn main() -> Result<(), Box<dyn Error>> {
    let token = "..."; // Your base64-encoded token here
    let cert_pem = fs::read_to_string("certs/certPem.pem")?;
    let private_pem = fs::read_to_string("certs/private.key")?;

    let encrypted_token = EncryptedToken::try_from_base64_str(token)?;
    let decrypted_token = encrypted_token.decrypt(&cert_pem, &private_pem)?;

    let pretty_json = serde_json::to_string_pretty(&decrypted_token).expect("Serialization failed");

    println!("{}", pretty_json);

    Ok(())
}
```

## Dependencies

This crate depends on the following crates:

```toml
base64 = "0.21.2"
hex = "0.4"
openssl = { version = "0.10", features = ["vendored"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
x509-certificate = "0.21.0"
```

## Examples

To run the included example:

- Make sure you have the required certificate and private key files in the `certs/` directory.
- Run the example using `cargo run --example decrypt`
- Check out the documentation for more details and usage instructions.
