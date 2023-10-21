build:
	cargo b --release

install: build
	sudo install ./target/release/mkcert2 /usr/bin/mkcert2

uninstall:
	sudo rm /usr/bin/mkcert2
