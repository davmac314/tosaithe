# Clone the dependencies here, so they can be built with the correct
# build flags, and automatically linked into tosaithe build.

if [ "${1:-}" = "https" ]; then
    git clone https://github.com/davmac314/bmcxxabi.git bmcxxabi
    git clone https://github.com/davmac314/bmunwind.git bmunwind
    git clone https://github.com/davmac314/libbmcxx.git libbmcxx
else
    git clone git@github.com:davmac314/bmcxxabi.git bmcxxabi
    git clone git@github.com:davmac314/bmunwind.git bmunwind
    git clone git@github.com:davmac314/libbmcxx.git libbmcxx
fi

git -c advice.detachedHead=false -C bmcxxabi checkout eb504acd75249e42dacb5e9117f823d5454a08d6
git -c advice.detachedHead=false -C bmunwind checkout 3a10d7046d1e3da920cc67b058f7625b6871ad52
git -c advice.detachedHead=false -C libbmcxx checkout f35b540d91378c43017fba91ccb93e6277901939
