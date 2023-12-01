#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

pub mod certs;

use certs::*;

use std::process::Command;
use certval::{CertFile, CertificateChain, CertificationPath, CertificationPathResults, CertificationPathSettings, CertVector, PDVCertificate, PDVTrustAnchorChoice, PkiEnvironment, TaSource, validate_path_rfc5280};
use serde_json::Value;
use x509_cert::der::{Decode, DecodePem, Encode, EncodePem};
use x509_cert::der::pem::LineEnding;

fn main() {
    pretty_print("target", TARGET);
    pretty_print("elna int", ELNA_INTERMEDIATE);
    pretty_print("elna root", ELNA_ROOT);
    validation_tryout()
}

fn validation_tryout() {
    let mut env = PkiEnvironment::new();

    let target = TARGET;
    let (elna_ta, diya_ta, r3) = (ELNA_ROOT, DIYA_ROOT, R3);
    let (elna_intermediate, diya_intermediate_cs_elna, elna_lets_encrypt) = (ELNA_INTERMEDIATE, DIYA_INTERMEDIATE_CROSS_SIGNED_ELNA, ELNA_LETS_ENCRYPT);
    let (elna_intermediate_cs_diya, diya_lets_encrypt) = (ELNA_INTERMEDIATE_CROSS_SIGNED_DIYA, DIYA_LETS_ENCRYPT);

    let mut ta_source = TaSource::new_from_unparsed(&[cert_to_der(elna_ta).as_slice(), cert_to_der(diya_ta).as_slice(), cert_to_der(r3).as_slice()]).unwrap();
    env.add_trust_anchor_source(Box::new(ta_source));

    // add all trust anchor
    let elna_ta = PDVTrustAnchorChoice::try_from(cert_to_der(elna_ta).as_slice()).unwrap();
    env.is_trust_anchor(&elna_ta).unwrap();
    let diya_ta = PDVTrustAnchorChoice::try_from(cert_to_der(diya_ta).as_slice()).unwrap();
    env.is_trust_anchor(&diya_ta).unwrap();
    let r3 = PDVTrustAnchorChoice::try_from(cert_to_der(r3).as_slice()).unwrap();
    env.is_trust_anchor(&r3).unwrap();

    let mut intermediates = CertificateChain::new();

    let elna_intermediate = PDVCertificate::try_from(cert_to_der(elna_intermediate).as_slice()).unwrap();
    let elna_intermediate_cs_diya = PDVCertificate::try_from(cert_to_der(elna_intermediate_cs_diya).as_slice()).unwrap();
    let elna_lets_encrypt = PDVCertificate::try_from(cert_to_der(elna_lets_encrypt).as_slice()).unwrap();

    let diya_intermediate_cs_elna = PDVCertificate::try_from(cert_to_der(diya_intermediate_cs_elna).as_slice()).unwrap();
    let diya_lets_encrypt = PDVCertificate::try_from(cert_to_der(diya_lets_encrypt).as_slice()).unwrap();
    intermediates.push(elna_intermediate.clone());
    intermediates.push(elna_intermediate_cs_diya.clone());
    intermediates.push(elna_lets_encrypt.clone());
    intermediates.push(diya_intermediate_cs_elna.clone());
    intermediates.push(diya_lets_encrypt.clone());

    let target = PDVCertificate::try_from(cert_to_der(target).as_slice()).unwrap();

    let cps = CertificationPathSettings::new();
    let mut cpr = CertificationPathResults::new();

    // let mut elna_cp = certval::CertificationPath::new(elna_ta.clone(), intermediates, elna_leaf.clone());
    // env.validate_path(&env, &cps, &mut elna_cp, &mut cpr).unwrap();
    // validate_path_rfc5280(&env, &cps, &mut cp, &mut cpr).unwrap();

    let mut cp = CertificationPath::new(elna_ta.clone(), intermediates, target.clone());
    validate_path_rfc5280(&env, &cps, &mut cp, &mut cpr).unwrap();
    // env.validate_path(&env, &cps, &mut cp, &mut cpr).unwrap();
}

fn cert_to_der(cert: &str) -> Vec<u8> {
    x509_cert::Certificate::from_pem(cert).and_then(|c| c.to_der()).unwrap()
}

fn pretty_print(label: &str, cert: &str) {
    let path = std::env::temp_dir().join(format!("cert.pem"));
    std::fs::write(&path, cert).unwrap();
    let path_str = path.to_str().unwrap();

    let out = Command::new("openssl")
        .args(&["x509", "-text", "-noout", "-in", path_str])
        .output().unwrap();

    let out = String::from_utf8(out.stdout).unwrap();
    println!("{label}: {out}\n============\n");
}

fn unfold() {
    let json = serde_json::from_str::<Value>(DIYA_RAW_CROSS_CHAIN).unwrap();
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

fn display_all() {
    pretty_print("elna root", ELNA_ROOT);
    pretty_print("diya intermediate signed by elna", DIYA_INTERMEDIATE_CROSS_SIGNED_ELNA);
    pretty_print("elna leaf signed by Let's Encrypt", ELNA_LETS_ENCRYPT);

    pretty_print("diya root", DIYA_ROOT);
    pretty_print("elna intermediate signed by diya", ELNA_INTERMEDIATE_CROSS_SIGNED_DIYA);
    pretty_print("diya leaf", DIYA_LETS_ENCRYPT);
}
