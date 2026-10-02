#!/bin/bash -eu
# leakkill is pure Python with no runtime dependencies: put the package on the path, no network needed.
cp -r "$SRC/leakkill/src/leakkill" "$(python3 -c 'import site; print(site.getsitepackages()[0])')/"
for fuzzer in "$SRC"/leakkill/fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
