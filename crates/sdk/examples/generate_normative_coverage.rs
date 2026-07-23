use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use a3s_oci_sdk::OciNormativeInventory;

fn main() -> Result<(), Box<dyn Error>> {
    let output = output_path()?;
    let manifest = OciNormativeInventory::new().coverage_baseline();
    let mut encoded = serde_json::to_vec_pretty(&manifest)?;
    encoded.push(b'\n');
    fs::write(&output, encoded)?;
    println!("wrote {}", output.display());
    Ok(())
}

fn output_path() -> Result<PathBuf, Box<dyn Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let output = arguments
        .next()
        .ok_or("usage: generate_normative_coverage <output.json>")?;
    if arguments.next().is_some() {
        return Err("usage: generate_normative_coverage <output.json>".into());
    }
    Ok(PathBuf::from(output))
}
