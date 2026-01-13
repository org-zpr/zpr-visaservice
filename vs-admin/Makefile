
.PHONY: all build test clean check completions clean-completions

all: build

build:
	cargo build --all-targets

test: build
	cargo test --verbose

check:
	cargo fmt --check && cargo rustc --bins -- -D warnings

clean:
	cargo clean

# Create the completion scripts for the CLI
TARGET_DIR = completions

.PHONY: completions
completions:
	cargo run --features complete --bin generate_completions -- --generate $(TARGET_DIR)

	@echo "\nInstallation of the completion script depends on your shell"
	@echo "\nBash: Source the file in your .bashrc or .bash_profile, or copy the file into one of the bash completions folders"
	@echo "\nZsh: There are several ways, including using oh-my-zsh, the zsh_completions package, or creating a symlink to your completions file in the ~/.local/share/zsh/site-functions/ then adding that to your fpath"
	@echo "\nElvish: 'Use' the file in ~/.config/elvish/rc.elv"
	@echo "\nFish: Copy the file into ~/.config/fish/completions/"
	@echo "\nPowerShell: Use 'Import-Module' to add the script to your user profile\n"

.PHONY: clean-completions
clean-completions:
	rm -r $(TARGET_DIR)



.DEFAULT_GOAL := all

