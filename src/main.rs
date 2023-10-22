use anyhow::{anyhow, bail, Result};
use dialoguer::{theme::ColorfulTheme, Confirm};
use std::{fs, path::PathBuf};

mod prompt;

#[derive(argh::FromArgs)]
/// mkcert2 made at https://github.com/ItsEthra/mkcert2
struct Args {
    /// domains to generate certificate for
    #[argh(positional)]
    domains: Vec<String>,
    /// create root certificate authority
    #[argh(switch)]
    install: bool,
    /// removes root certificate authority
    #[argh(switch)]
    remove: bool,
    /// time the certificate is valid for
    #[argh(option, default = "String::from(\"1y\")")]
    valid: String,
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();
    if args.install {
        prompt::create_root_ca(&args)?;
        return Ok(());
    } else if args.remove {
        fs::remove_dir_all(get_ca_dir())?;
        println!("Removed root CA");
        return Ok(());
    } else if args.domains.is_empty() {
        bail!("You need to specify at least 1 domain");
    }

    let ca = prompt::get_root_ca(&args)?;
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

    let cert = prompt::create_new_cert(false, &args)?;
    fs::write("cert.pem", cert.serialize_pem_with_signer(&ca)?)?;
    fs::write("cert-key.pem", cert.serialize_private_key_pem())?;

    Ok(())
}

pub fn get_ca_dir() -> PathBuf {
    dirs::data_dir()
        .expect("data_dir must be available")
        .join("mkcert2")
}
