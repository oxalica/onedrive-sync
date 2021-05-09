{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs.buildPackages; [
    pkg-config
    sqlite.out
    sqlite-interactive
    openssl
  ];
}
