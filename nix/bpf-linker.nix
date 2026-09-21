{ pkgs }:

let
  version = "0.11.1";
  assets = {
    x86_64-linux = {
      url = "https://github.com/aya-rs/bpf-linker/releases/download/v${version}/bpf-linker-x86_64-unknown-linux-musl.tar.zst";
      hash = "sha256-4FimrsyeZfpMl3spio5Lc4Qk12KXaf01Lu1An7V+Fug=";
    };
    aarch64-linux = {
      url = "https://github.com/aya-rs/bpf-linker/releases/download/v${version}/bpf-linker-aarch64-unknown-linux-musl.tar.zst";
      hash = "sha256-NB7BxZVJaHfK4rBzVEwiJteKkic5YytXMtuqSFB/E4A=";
    };
  };
  asset =
    assets.${pkgs.system} or (throw "bpf-linker ${version} has no release asset for ${pkgs.system}");
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "bpf-linker";
  inherit version;
  src = pkgs.fetchurl asset;

  nativeBuildInputs = [
    pkgs.gnutar
    pkgs.zstd
  ];
  dontUnpack = true;
  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    mkdir -p "$out/bin"
    tar --use-compress-program=unzstd -xf "$src" -C "$out/bin"
    chmod +x "$out/bin/bpf-linker"
  '';
}
