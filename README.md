# Secure Automated File Organizer

![Python Tests](https://github.com/IsaDoom/File-Migration/actions/workflows/tests.yaml/badge.svg)

A robust Python CLI tool that automatically categorizes incoming files and ensures zero data loss using SHA-256 cryptographic hashing. Originally built to mitigate silent file corruption during hardware failure, this tool guarantees that every byte transferred matches the original source.

## System Architecture

* **Cryptographic Integrity:** Computes SHA-256 hashes of every file before and after moving. If a mismatch is detected, the operation is aborted and the corrupted destination file is safely quarantined.
* **Append-Only Manifest:** Every successful transfer is written to a hash-chained `manifest.jsonl` log. Altering or deleting past log entries breaks the chain, providing a tamper-evident audit trail.
* **Continuous Monitoring:** Runs a polling watcher to safely migrate files only after downloads or external transfers are completely finished (checking file size and mtime intervals).

## Installation

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/IsaDoom/File-Migration.git
cd File-Migration
pip install -r requirements.txt