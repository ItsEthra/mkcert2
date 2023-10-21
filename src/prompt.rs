use anyhow::{anyhow, Result};
use dialoguer::{
    theme::{ColorfulTheme, Theme},
    Confirm, Input, InputValidator,
};
use indicatif::{ProgressBar, ProgressStyle};
use names::Generator;
use rand::rngs::OsRng;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType, PKCS_RSA_SHA256,
};
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};
use std::{fs, net::IpAddr, str::FromStr};
use time::Duration;

use crate::get_ca_dir;

fn autofill(dn: &mut DistinguishedName) {
    let name_host = format!("{}@{}", whoami::username(), whoami::hostname());
    let values = [
        DnType::CountryName,
        DnType::OrganizationName,
        DnType::CommonName,
    ];

    values.into_iter().for_each(|v| dn.push(v, &name_host));
}

pub fn distinguished_name() -> Result<DistinguishedName> {
    let theme: &dyn Theme = &ColorfulTheme::default();

    let mut out = DistinguishedName::new();
    let name = move || Generator::default().next().unwrap();

    let skip = Confirm::with_theme(theme)
        .with_prompt("Autofill distinguished name")
        .default(true)
        .interact()?;
    if skip {
        autofill(&mut out);
        return Ok(out);
    }

    macro_rules! prompt {
        ($($prompt:literal, $dnty:ident),*) => {
            $(
                let value: String = Input::with_theme(theme)
                    .with_prompt($prompt)
                    .default(name())
                    .interact()?;
                out.push(DnType::$dnty, value);
            )*
        };
    }

    prompt!(
        "Country name",
        CountryName,
        "Locality name",
        LocalityName,
        "State or province name",
        StateOrProvinceName,
        "Organization name",
        OrganizationName,
        "Organization unit name",
        OrganizationalUnitName,
        "Common name",
        CommonName
    );

    Ok(out)
}

pub fn valid_duration() -> Result<Duration> {
    struct Validator;
    impl InputValidator<String> for Validator {
        type Err = parse_duration::parse::Error;

        fn validate(&mut self, input: &String) -> std::result::Result<(), Self::Err> {
            parse_duration::parse(input)?;
            Ok(())
        }
    }

    let valid_duration: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Valid for")
        .default("1y".to_owned())
        .validate_with(Validator)
        .interact()?;
    let duration = parse_duration::parse(&valid_duration)?;
    Ok(duration.try_into()?)
}

pub fn get_root_ca() -> Result<Certificate> {
    let dir = get_ca_dir();

    if !dir.exists() {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to create a root CA?")
            .default(true)
            .interact()?
            .then_some(())
            .ok_or(anyhow!("Root CA is required"))?;
        let cert = create_new_cert(true)?;

        fs::create_dir_all(&dir)?;
        fs::write(dir.join("rootCA-cert.pem"), cert.serialize_pem()?)?;
        fs::write(dir.join("rootCA-key.pem"), cert.serialize_private_key_pem())?;

        println!("Created root CA in {dir:?}");
    } else {
        println!("Using existing root CA from {dir:?}");
    }

    let read = |name: &str| fs::read_to_string(dir.join(name));
    let cert_pem = read("rootCA-cert.pem")?;
    let key_pem = read("rootCA-key.pem")?;

    let keypair = KeyPair::from_pem(&key_pem)?;
    let params = CertificateParams::from_ca_cert_pem(&cert_pem, keypair)?;
    let cert = Certificate::from_params(params)?;

    Ok(cert)
}

fn prompt_alt_names() -> Result<Vec<SanType>> {
    let domains: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Domains")
        .interact_text()?;

    let types = domains
        .split(',')
        .map(str::trim)
        .map(|x| IpAddr::from_str(x).map_err(|_| x))
        .map(|x| match x {
            Ok(ip) => SanType::IpAddress(ip),
            Err(dns) => SanType::DnsName(dns.to_owned()),
        })
        .collect::<Vec<_>>();

    Ok(types)
}

pub fn create_new_cert(ca: bool) -> Result<Certificate> {
    let distinguished_name = distinguished_name()?;
    let valid_for = valid_duration()?;

    let subject_alt_names = if !ca { prompt_alt_names()? } else { vec![] };

    let spinner_style = ProgressStyle::with_template("{spinner} {wide_msg}")
        .unwrap()
        .tick_chars("⣾⣽⣻⢿⡿⣟⣯⣷");
    let bar = ProgressBar::new_spinner()
        .with_message("Generating private key")
        .with_style(spinner_style);
    bar.enable_steady_tick((100_i32 * Duration::MILLISECOND).try_into()?);

    let private = RsaPrivateKey::new(&mut OsRng, 2048)?;
    bar.finish_and_clear();

    let keypair = KeyPair::from_der(private.to_pkcs8_der()?.as_bytes())?;

    let now = time::OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();

    if ca {
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    } else {
        params.is_ca = IsCa::ExplicitNoCa;
    }
    params.alg = &PKCS_RSA_SHA256;
    params.subject_alt_names = subject_alt_names;
    params.not_before = now - Duration::DAY;
    params.not_after = now + valid_for;
    params.key_pair = Some(keypair);
    params.key_usages = if ca {
        vec![KeyUsagePurpose::KeyCertSign]
    } else {
        vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ]
    };

    if !ca {
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    }

    params.distinguished_name = distinguished_name;

    let cert = Certificate::from_params(params)?;

    Ok(cert)
}
