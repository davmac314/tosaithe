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
