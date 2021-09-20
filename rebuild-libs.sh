# Rebuild the dependencies.

rm -f lib/libbmcxx.a lib/libcxxabi.a lib/libunwind.a
(cd bmcxxabi; make clean)
(cd libbmcxx; make clean)
(cd bmunwind; make clean)
mkdir lib
make lib/libcxxabi.a
make lib/libbmcxx.a
make lib/libunwind.a
