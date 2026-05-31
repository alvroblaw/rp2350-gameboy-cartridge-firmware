# =============================================================================
# RP2350 GameBoy Cartridge Dev Container
# Self-contained build: Debian-based, sdcc + GBDK compiled from source
# Supports: linux/amd64, linux/arm64 (Apple Silicon native)
# =============================================================================

FROM debian:bookworm-slim AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        subversion \
        python3 \
        python3-pip \
        curl \
        build-essential \
        libusb-1.0-0-dev \
        cmake \
        gdb-multiarch \
        binutils \
        libbz2-1.0 \
        openssh-client \
        ca-certificates \
        # sdcc build deps
        bison \
        flex \
        libboost-all-dev \
        texinfo \
        zlib1g-dev \
        libpng-dev \
        # ARM toolchain
        gcc-arm-none-eabi \
        libnewlib-arm-none-eabi \
        # clang tools (for formatting etc.)
        clang-format \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Rust toolchain
# =============================================================================
ENV RUSTUP_HOME="/usr/local/rustup"
ENV CARGO_HOME="/usr/local/cargo"
ENV PATH="/usr/local/cargo/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
    --default-toolchain 1.85.0 -y && \
    rustup target add thumbv8m.main-none-eabihf && \
    cargo install --version 0.3.6 cargo-binutils && \
    rustup component add llvm-tools

# =============================================================================
# Raspberry Pi Pico SDK
# =============================================================================
ARG SDK_PATH=/usr/share/pico_sdk
RUN git clone --depth 1 --branch 2.1.1 \
    https://github.com/raspberrypi/pico-sdk "${SDK_PATH}" && \
    cd "${SDK_PATH}" && git submodule update --init
ENV PICO_SDK_PATH=${SDK_PATH}

# =============================================================================
# Picotool
# =============================================================================
RUN git clone --depth 1 --branch 2.1.1 \
    https://github.com/raspberrypi/picotool.git /tmp/picotool && \
    cd /tmp/picotool && mkdir build && cd build && \
    cmake .. && make -j$(nproc) && \
    cp picotool /usr/local/bin/ && \
    rm -rf /tmp/picotool

# =============================================================================
# sdcc (patched for GBDK) — built from source
# This is the slow part (~10-20 min). Keeps its own layer for caching.
# =============================================================================
ARG GBDK_PATH=/usr/share/gbdk

RUN svn checkout -q -r r14228 svn://svn.code.sf.net/p/sdcc/code/trunk /tmp/sdcc-r14228 && \
    cd /tmp/sdcc-r14228/sdcc && \
    curl -Lo gbdk-sdcc-patch-file \
        https://github.com/gbdk-2020/gbdk-2020-sdcc/releases/download/patches/gbdk-4.2-nes_banked_nonbanked_v4_combined.diff.patch && \
    patch -p0 -f < gbdk-sdcc-patch-file && \
    ./configure \
        --disable-shared \
        --enable-gbz80-port --enable-z80-port --enable-mos6502-port --enable-mos65c02-port \
        --disable-mcs51-port --disable-z180-port --disable-r2k-port --disable-r2ka-port \
        --disable-r3ka-port --disable-tlcs90-port --disable-ez80_z80-port --disable-z80n-port \
        --disable-ds390-port --disable-ds400-port --disable-pic14-port --disable-pic16-port \
        --disable-hc08-port --disable-s08-port --disable-stm8-port --disable-pdk13-port \
        --disable-pdk14-port --disable-pdk15-port --disable-ucsim --disable-doc --disable-device-lib && \
    make -j$(nproc) && \
    cp -f src/sdcc bin/ && \
    cp -f support/sdbinutils/binutils/sdar bin/ && \
    cp -f support/sdbinutils/binutils/sdranlib bin/ && \
    cp -f support/sdbinutils/binutils/sdobjcopy bin/ && \
    cp -f support/sdbinutils/binutils/sdnm bin/ && \
    cp -f support/cpp/gcc/cc1 bin/ && \
    cp -f support/cpp/gcc/cpp bin/sdcpp && \
    strip bin/* || true && \
    rm -f bin/*.in bin/Makefile bin/README && \
    mkdir -p libexec/sdcc && \
    mv bin/cc1 libexec/sdcc/ && \
    echo "sdcc build complete"

# =============================================================================
# GBDK 4.2.0 — built on top of patched sdcc
# =============================================================================
RUN export SDCCDIR=/tmp/sdcc-r14228/sdcc && \
    git clone -b 4.2.0 https://github.com/gbdk-2020/gbdk-2020.git /tmp/gbdk-2020 && \
    cd /tmp/gbdk-2020 && make -j$(nproc) && \
    cp -R build/gbdk "${GBDK_PATH}" && \
    rm -rf /tmp/sdcc-r14228 /tmp/gbdk-2020

ENV GBDK_PATH=${GBDK_PATH}

# =============================================================================
# Final setup
# =============================================================================
WORKDIR /workspaces/rp2350-gameboy-cartridge-firmware

CMD ["bash"]
