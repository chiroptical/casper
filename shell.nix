{ pkgs, ... }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    gleam
    rebar3
    erlang

    nodePackages.nodejs

    nixfmt-rfc-style
  ];
}
