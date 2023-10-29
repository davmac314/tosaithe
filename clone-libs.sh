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

git -c advice.detachedHead=false -C bmcxxabi checkout 834aff7495f4bae9d3b839eb6659485cf5683751
git -c advice.detachedHead=false -C bmunwind checkout 4ee7583c10b6993e2c65955cba2e3ed2d32e829e
git -c advice.detachedHead=false -C libbmcxx checkout 65c65c257eda35a5966daa1d3efd37eb6401f8bb
