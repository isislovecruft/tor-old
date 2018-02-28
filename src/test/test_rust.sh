#!/bin/sh

cd "${abs_top_builddir:-../..}/src/rust"

CARGO_TARGET_DIR="$PWD/target"
CARGO_HOME="$PWD"
RUSTFLAGS="-L ${PWD%/rust}/or -L ${PWD%/rust}/common -L ${PWD%/rust}/ext/keccak-tiny -L ${PWD%/rust}/ext/ed25519/ref10 -L ${PWD%/rust}/ext/ed25519/donna -L ${PWD%/rust}/trunnel -L ${PWD%/rust}/trace -l static=tor-testing -l static=or-crypto-testing -l static=or-testing -l static=or-ctime-testing -l static=or-event-testing -l static=or-trunnel-testing -l static=or-trace -l static=curve25519_donna -l static=keccak-tiny -l static=ed25519_ref10 -l static=ed25519_donna -l ssl -l crypto -l zstd -l seccomp -lcap -levent -lz -llzma -lsystemd"
export CARGO_TARGET_DIR CARGO_HOME RUSTFLAGS

exec "${CARGO:-cargo}" test ${CARGO_ONLINE-"--frozen"} --all --verbose
