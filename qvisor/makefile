.PHONY: debug release

debug:
	RUSTFLAGS="--cfg aes_force_soft --cfg polyval_force_soft" CARGO_TARGET_DIR=../target cargo build

release:
	RUSTFLAGS="--cfg aes_force_soft --cfg polyval_force_soft" CARGO_TARGET_DIR=../target cargo build --release

