# Rust library for Ledger Dfinity app
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CircleCI](https://circleci.com/gh/Zondax/ledger-dfinity-rs.svg?style=shield&circle-token=58fb41ff627c28a980534596b61450adacf65689)](https://circleci.com/gh/Zondax/ledger-dfinity-rs)

This package provides a basic Rust client library to communicate with the Dfinity App running in a Ledger Nano S/X devices

## Build

- Install rust using the instructions [here](https://www.rust-lang.org/tools/install)
- To build run:
```shell script
cargo build
```

## Run Tests
To run the tests

- Initialize your device with the test mnemonic. More info [here](https://github.com/zondax/ledger-dfinity#how-to-prepare-your-development-device)
- run tests using: 
```shell script
cargo test --all
```
