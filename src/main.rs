#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

pub mod certs;

use certs::*;

use std::process::Command;
use certval::{CertFile, CertificateChain, CertificationPathResults, CertificationPathSettings, CertVector, PDVCertificate, PDVTrustAnchorChoice, PkiEnvironment, TaSource, validate_path_rfc5280};
use serde_json::Value;
use x509_cert::der::{DecodePem, Encode};

fn main() {
    display_all()
}

fn validation_tryout() {
    let mut env = PkiEnvironment::new();

    let (elna_ta, elna_intermediate, elna_leaf) = (ELNA_ROOT, ELNA_INTERMEDIATE, ELNA_LEAF);
    let (diya_ta, diya_intermediate, diya_leaf) = (DIYA_ROOT, DIYA_INTERMEDIATE, DIYA_LEAF);

    let mut ta_source = TaSource::new_from_unparsed(&[cert_to_der(elna_ta).as_slice(), cert_to_der(diya_ta).as_slice()]).unwrap();
    env.add_trust_anchor_source(Box::new(ta_source));

    let elna_ta = PDVTrustAnchorChoice::try_from(cert_to_der(elna_ta).as_slice()).unwrap();
    env.is_trust_anchor(&elna_ta).unwrap();
    let diya_ta = PDVTrustAnchorChoice::try_from(cert_to_der(diya_ta).as_slice()).unwrap();
    env.is_trust_anchor(&diya_ta).unwrap();

    let mut intermediates = CertificateChain::new();
    let elna_intermediate = PDVCertificate::try_from(cert_to_der(elna_intermediate).as_slice()).unwrap();
    let diya_intermediate = PDVCertificate::try_from(cert_to_der(diya_intermediate).as_slice()).unwrap();
    intermediates.push(elna_intermediate.clone());
    intermediates.push(diya_intermediate.clone());

    let elna_leaf = PDVCertificate::try_from(cert_to_der(elna_leaf).as_slice()).unwrap();
    let diya_leaf = PDVCertificate::try_from(cert_to_der(diya_leaf).as_slice()).unwrap();

    let mut elna_cp = certval::CertificationPath::new(elna_ta.clone(), intermediates, elna_leaf.clone());

    let cps = CertificationPathSettings::new();
    let mut cpr = CertificationPathResults::new();

    // env.validate_path(&env, &cps, &mut elna_cp, &mut cpr).unwrap();


    // validate_path_rfc5280(&env, &cps, &mut cp, &mut cpr).unwrap();
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
    pretty_print("diya intermediate signed by elna", ELNA_INTERMEDIATE);
    pretty_print("elna leaf signed by Let's Encrypt", ELNA_LEAF);

    pretty_print("diya root", DIYA_ROOT);
    pretty_print("elna intermediate signed by diya", DIYA_INTERMEDIATE);
    pretty_print("diya leaf", DIYA_LEAF);

}
