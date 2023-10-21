use anyhow::{anyhow, Result};
use dialoguer::{theme::ColorfulTheme, Confirm};
use std::{fs, path::PathBuf};

mod prompt;

fn main() -> Result<()> {
    let ca = prompt::get_root_ca()?;

    println!("Creating new certificate in the current directory");

    let exists = |path: &str| PathBuf::from(path).exists();
    if exists("cert.pem") || exists("cert-key.pem") {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("`cert.pem` or `cert-key.pem` already exist, do you want to overwrite?")
            .default(false)
            .interact()?
            .then_some(())
            .ok_or(anyhow!("Not overwriting"))?;
    }

    let cert = prompt::create_new_cert(false)?;
    fs::write("cert.pem", cert.serialize_pem_with_signer(&ca)?)?;
    fs::write("cert-key.pem", cert.serialize_private_key_pem())?;

    Ok(())
}

pub fn get_ca_dir() -> PathBuf {
    dirs::data_dir()
        .expect("data_dir must be available")
        .join("mkcert2")
}
