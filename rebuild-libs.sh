# Rebuild the dependencies.

set -e

rm -f lib/libbmcxx.a lib/libcxxabi.a lib/libunwind.a
(cd bmcxxabi; make clean)
(cd libbmcxx; make clean)
(cd bmunwind; make clean)
mkdir -p lib
make lib/libcxxabi.a
make lib/libbmcxx.a
make lib/libunwind.a
