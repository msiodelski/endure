use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::{fs::File, io::Read, path::PathBuf, process::Command};
use tempdir::TempDir;

/// Convenience function returning a path to a test `pcap` file.
fn resource_path(pcap_name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/resources/pcap");
    path.push(pcap_name);
    path.as_os_str().to_str().unwrap().to_owned()
}

#[test]
fn cli_collect_interface_name_unspecified() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;

    cmd.arg("collect").arg("-i");
    cmd.assert().failure().stderr(predicate::str::contains(
        "'--interface-name <INTERFACE_NAME>' but none was supplied",
    ));

    Ok(())
}

#[test]
fn cli_collect_interface_name_not_exists() -> Result<(), Box<dyn std::error::Error>> {
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
fn cli_collect_interface_name_repeated() -> Result<(), Box<dyn std::error::Error>> {
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
fn cli_collect_loopback_interface_name_collision() -> Result<(), Box<dyn std::error::Error>> {
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
fn cli_collect_interface_name_not_specified() -> Result<(), Box<dyn std::error::Error>> {
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
fn cli_collect_no_reporting() -> Result<(), Box<dyn std::error::Error>> {
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
fn cli_collect_address_malformed() -> Result<(), Box<dyn std::error::Error>> {
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
fn cli_collect_no_address_specified_for_sse() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect").arg("-i").arg("foo").arg("--sse");
    cmd.assert().failure().stderr(predicate::str::contains(
        "'http_address' is required when using '--prometheus', '--api' or '--sse flags",
    ));
    Ok(())
}

#[test]
fn cli_collect_no_address_specified_for_prometheus() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect").arg("-i").arg("foo").arg("--prometheus");
    cmd.assert().failure().stderr(predicate::str::contains(
        "'http_address' is required when using '--prometheus', '--api' or '--sse flags",
    ));
    Ok(())
}

#[test]
fn cli_collect_no_address_specified_for_api() -> Result<(), Box<dyn std::error::Error>> {
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
fn cli_collect_address_specified_no_sse_nor_prometheus_nor_api(
) -> Result<(), Box<dyn std::error::Error>> {
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
fn cli_collect_zero_report_interval() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect").arg("-i").arg("foo").arg("-r").arg("0");
    cmd.assert().failure().stderr(predicate::str::contains(
                "invalid value '0' for '--report-interval <REPORT_INTERVAL>': 0 is not in 1..18446744073709551615"
            ));
    Ok(())
}

#[test]
fn cli_collect_csv_output_directory_non_existing() -> Result<(), Box<dyn std::error::Error>> {
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
fn cli_collect_pcap_directory_non_existing() -> Result<(), Box<dyn std::error::Error>> {
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
fn cli_collect_directory_path_not_directory() -> Result<(), Box<dyn std::error::Error>> {
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

#[test]
fn cli_collect_sampling_window_size_out_of_range() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("collect")
        .arg("-i")
        .arg("foo")
        .arg("-a")
        .arg("127.0.0.1:8080")
        .arg("--sse")
        .arg("-s")
        .arg("65536");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("65536 is not in 1..65536"));
    Ok(())
}

#[test]
fn cli_read_csv() -> Result<(), Box<dyn std::error::Error>> {
    // This predicate checks the CSV output presence.
    let predicate = predicate::str::is_match("((\\S\\,)+\\S)").unwrap();
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("read")
        .arg("--csv")
        .arg("--pcap")
        .arg(resource_path("capture000.pcap"));
    cmd.assert().success().stdout(predicate);
    Ok(())
}

#[test]
fn cli_read_csv_stream() -> Result<(), Box<dyn std::error::Error>> {
    // This predicate checks the CSV output presence.
    let predicate = predicate::str::is_match("((\\S\\,)+\\S)").unwrap();
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("read")
        .arg("--csv")
        .arg("--stream")
        .arg("--pcap")
        .arg(resource_path("capture000.pcap"));
    cmd.assert().success().stdout(predicate);
    Ok(())
}

#[test]
fn cli_read_json() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("read")
        .arg("--json")
        .arg("--pcap")
        .arg(resource_path("capture000.pcap"));
    cmd.assert()
        .success()
        .stdout(predicate::str::starts_with("{"))
        .stdout(predicate::str::ends_with("}\n"));
    Ok(())
}

#[test]
fn cli_read_to_file() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new("test").unwrap();
    let report_path = dir.path().join("reports.json");
    let report_path_str = report_path
        .as_os_str()
        .to_os_string()
        .into_string()
        .unwrap();

    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("read")
        .arg("--json")
        .arg("--pcap")
        .arg(resource_path("capture000.pcap"))
        .arg("--output")
        .arg(&report_path);
    cmd.assert().success();

    assert!(report_path.exists());
    let file = File::open(report_path_str);
    assert!(file.is_ok());

    let mut file = file.unwrap();
    let mut buf = String::new();
    let result = file.read_to_string(&mut buf);
    assert!(result.is_ok());
    assert!(buf.starts_with("{"));
    Ok(())
}

#[test]
fn cli_read_json_stream_not_allowed() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("read")
        .arg("--json")
        .arg("--stream")
        .arg("--pcap")
        .arg(resource_path("capture000.pcap"));
    cmd.assert().stderr(predicate::str::contains(
        "the argument '--stream' cannot be used with '--json'",
    ));
    Ok(())
}

#[test]
fn cli_read_format_unspecified() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("read")
        .arg("--pcap")
        .arg(resource_path("capture000.pcap"));
    cmd.assert().stderr(
        predicate::str::contains("the following required arguments were not provided")
            .and(predicate::str::contains("  <--csv|--json>")),
    );
    Ok(())
}

#[test]
fn cli_read_pcap_unspecified() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("read").arg("--csv");
    cmd.assert().stderr(
        predicate::str::contains("the following required arguments were not provided")
            .and(predicate::str::contains("  --pcap <PCAP>")),
    );
    Ok(())
}

#[test]
fn cli_read_sampling_window_size_out_of_range() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("read")
        .arg("--sampling-window-size")
        .arg("65536")
        .arg("--json")
        .arg("--pcap")
        .arg(resource_path("capture000.pcap"));
    cmd.assert()
        .stderr(predicate::str::contains("65536 is not in 1..65536"));
    Ok(())
}

#[test]
fn cli_read_sampling_window_size_pcap_full() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("read")
        .arg("--sampling-window-size")
        .arg("65533")
        .arg("--csv")
        .arg("--pcap")
        .arg(resource_path("capture000.pcap"));
    cmd.assert().stderr(predicate::str::contains(
        "the argument '--sampling-window-size' cannot be used with '--csv (without --stream)'",
    ));
    Ok(())
}

#[test]
fn cli_read_sampling_window_size_json() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("endure")?;
    cmd.arg("read")
        .arg("--sampling-window-size")
        .arg("65533")
        .arg("--json")
        .arg("--pcap")
        .arg(resource_path("capture000.pcap"));
    cmd.assert().stderr(predicate::str::contains(
        "the argument '--sampling-window-size' cannot be used with '--json'",
    ));
    Ok(())
}
