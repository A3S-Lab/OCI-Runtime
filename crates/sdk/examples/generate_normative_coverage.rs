use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use a3s_oci_sdk::{OciNormativeEvidenceManifest, OciNormativeInventory};

fn main() -> Result<(), Box<dyn Error>> {
    let (evidence_path, output) = paths()?;
    let evidence: OciNormativeEvidenceManifest =
        serde_json::from_slice(&fs::read(&evidence_path)?)?;
    let manifest = OciNormativeInventory::new().coverage_with_evidence(&evidence)?;
    let mut encoded = serde_json::to_vec_pretty(&manifest)?;
    encoded.push(b'\n');
    fs::write(&output, encoded)?;
    println!("wrote {}", output.display());
    Ok(())
}

fn paths() -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let evidence = arguments
        .next()
        .ok_or("usage: generate_normative_coverage <evidence.json> <output.json>")?;
    let output = arguments
        .next()
        .ok_or("usage: generate_normative_coverage <evidence.json> <output.json>")?;
    if arguments.next().is_some() {
        return Err("usage: generate_normative_coverage <evidence.json> <output.json>".into());
    }
    Ok((PathBuf::from(evidence), PathBuf::from(output)))
}
