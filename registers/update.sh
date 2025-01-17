# Licensed under the Apache-2.0 license

cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ ! -f "../hw-latest/caliptra-rtl/.git" ]]; then
    echo "caliptra-rtl submodule is not populated"
    echo "Please run 'git submodule update --init'"
    exit 1
fi

cargo run --manifest-path bin/generator/Cargo.toml -- ../hw-latest/caliptra-rtl bin/extra-rdl/ src/
