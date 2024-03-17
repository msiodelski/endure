use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::{fs::File, process::Command};
use tempdir::TempDir;

#[test]
fn cli_interface_name_unspecified() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;

    cmd.arg("collect").arg("-i");
    cmd.assert().failure().stderr(predicate::str::contains(
        "'--interface-name <INTERFACE_NAME>' but none was supplied",
    ));

    Ok(())
}

#[test]
fn cli_interface_name_not_exists() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;

    cmd.arg("collect")
        .arg("-i")
        .arg("unusual_interface_name")
        .arg("-c")
        .arg("stdout");
    cmd.assert().failure().stderr(predicate::str::contains(
        "starting the traffic capture failed: \"libpcap error: No such device exists\"",
    ));
    Ok(())
}

#[test]
fn cli_interface_name_repeated() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;

    cmd.arg("collect")
        .arg("-i")
        .arg("foo")
        .arg("--interface-name")
        .arg("foo")
        .arg("-c")
        .arg("stdout");
    cmd.assert().failure().stderr(predicate::str::contains(
        "specified the same interface \"foo\" multiple names",
    ));
    Ok(())
}

#[test]
fn cli_loopback_interface_name_collision() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;

    cmd.arg("collect")
        .arg("--loopback")
        .arg("--interface-name")
        .arg("foo")
        .arg("-c")
        .arg("stdout");
    cmd.assert().failure().stderr(predicate::str::contains(
        "the argument '--loopback' cannot be used with '--interface-name <INTERFACE_NAME>'",
    ));
    Ok(())
}

#[test]
fn cli_interface_name_not_specified() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;

    cmd.arg("collect");
    cmd.assert().failure().stderr(
        predicate::str::contains("the following required arguments were not provided:").and(
            predicate::str::contains("--interface-name <INTERFACE_NAME>"),
        ),
    );
    Ok(())
}

#[test]
fn cli_no_reporting() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect").arg("-i").arg("foo");
    cmd.assert().failure().stderr(
        predicate::str::contains("the following required arguments were not provided").and(
            predicate::str::contains("<--csv-output <CSV_OUTPUT>|--prometheus|--api|--sse>"),
        ),
    );
    Ok(())
}

#[test]
fn cli_address_malformed() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect")
        .arg("-i")
        .arg("foo")
        .arg("-a")
        .arg("127.0.0.1:")
        .arg("--sse");
    cmd.assert().failure().stderr(predicate::str::contains(
        "failed to start an HTTP service: \"invalid port value\"",
    ));
    Ok(())
}

#[test]
fn cli_no_address_specified_for_sse() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect").arg("-i").arg("foo").arg("--sse");
    cmd.assert().failure().stderr(predicate::str::contains(
        "'http_address' is required when using '--prometheus', '--api' or '--sse flags",
    ));
    Ok(())
}

#[test]
fn cli_no_address_specified_for_prometheus() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect").arg("-i").arg("foo").arg("--prometheus");
    cmd.assert().failure().stderr(predicate::str::contains(
        "'http_address' is required when using '--prometheus', '--api' or '--sse flags",
    ));
    Ok(())
}

#[test]
fn cli_no_address_specified_for_api() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect")
        .arg("-i")
        .arg("foo")
        .arg("--api")
        .arg("-c")
        .arg("stdout");
    cmd.assert().failure().stderr(predicate::str::contains(
        "'http_address' is required when using '--prometheus', '--api' or '--sse flags",
    ));
    Ok(())
}

#[test]
fn cli_address_specified_no_sse_nor_prometheus_nor_api() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect")
        .arg("-i")
        .arg("foo")
        .arg("-a")
        .arg("127.0.0.1:8090")
        .arg("-c")
        .arg("stdout");
    cmd.assert().failure().stderr(predicate::str::contains(
        "'http_address' is only valid with '--prometheus', '--api' and '--sse' flags",
    ));
    Ok(())
}

#[test]
fn cli_zero_report_interval() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect").arg("-i").arg("foo").arg("-r").arg("0");
    cmd.assert().failure().stderr(predicate::str::contains(
                "invalid value '0' for '--report-interval <REPORT_INTERVAL>': 0 is not in 1..18446744073709551615"
            ));
    Ok(())
}

#[test]
fn cli_csv_output_directory_non_existing() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect")
        .arg("-i")
        .arg("foo")
        .arg("-c")
        .arg("/tmp/non-existing/file.csv");
    cmd.assert().failure().stderr(predicate::str::contains(
        "directory \"/tmp/non-existing\" does not exist",
    ));
    Ok(())
}

#[test]
fn cli_pcap_directory_non_existing() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect")
        .arg("-i")
        .arg("foo")
        .arg("-p")
        .arg("/tmp/non-existing/endure/directory");
    cmd.assert().failure().stderr(predicate::str::contains(
        "directory \"/tmp/non-existing/endure/directory\" does not exist",
    ));
    Ok(())
}

#[test]
fn cli_directory_path_not_directory() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new("test")?;
    let file_path = dir.path().join("tcp.pcap");
    let _ = File::create(&file_path)?;
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect")
        .arg("-i")
        .arg("foo")
        .arg("-p")
        .arg(file_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("tcp.pcap\" is not a directory"));
    Ok(())
}
