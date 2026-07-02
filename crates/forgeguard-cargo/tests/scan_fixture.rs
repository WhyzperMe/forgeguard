use forgeguard_cargo::parse_lockfile_path;
use std::path::PathBuf;

#[test]
fn scans_fixture_cargo_lock() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/cargo/vulnerable-Cargo.lock");

    let graph = parse_lockfile_path(&fixture).expect("fixture lockfile should parse");

    assert_eq!(graph.packages.len(), 1);
    assert_eq!(graph.packages[0].id.name, "time");
    assert_eq!(graph.packages[0].purl, "pkg:cargo/time@0.1.44");
}
