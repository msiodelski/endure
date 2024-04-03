//! endure is a DHCP diagnostics tool.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![deny(rustdoc::missing_crate_level_docs)]
#![deny(rustdoc::invalid_codeblock_attributes)]
#![deny(rustdoc::invalid_html_tags)]
#![deny(rustdoc::invalid_rust_codeblocks)]
#![deny(rustdoc::bare_urls)]
#![deny(rustdoc::unescaped_backticks)]
#![deny(rustdoc::redundant_explicit_links)]

use clap::Parser;
use cli::Cli;

pub mod analyzer;
pub mod auditor;
pub mod cli;
pub mod dispatcher;
pub mod pcap_processor;
pub mod proto;
pub mod sse;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    cli.run();
}
