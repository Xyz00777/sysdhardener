{
  pkgs ? import <nixpkgs> { },
}:

# Keep the non-flake shell on the same package expression as flake.nix.
# (Both entry points consume `nix/dependencies.nix` and that file is the
# single source of truth.)
#
# The host nixpkgs is unconstrained (the caller passes it, or the implicit
# `<nixpkgs>` is resolved by their nix-channel). If the host nixpkgs
# ships rustc older than the workspace MSRV (1.85), the shell fails
# immediately with a clear assertion message rather than silently
# entering a shell that cannot build the workspace.

let
  bpfLinker = import ./nix/bpf-linker.nix { inherit pkgs; };
  dependencies = import ./nix/dependencies.nix { inherit pkgs bpfLinker; };
  rustc = pkgs.rustc or null;
  hasRustc = rustc != null && rustc ? version;
  rustcVersion = if hasRustc then rustc.version else "missing";
  rustcVersionParts =
    if hasRustc then
      pkgs.lib.splitString "." rustcVersion
    else
      [
        "0"
        "0"
      ];
  rustcMajor = pkgs.lib.toInt (pkgs.lib.elemAt rustcVersionParts 0);
  rustcMinor = pkgs.lib.toInt (pkgs.lib.elemAt rustcVersionParts 1);
  msrvMajor = 1;
  msrvMinor = 85;
  msrvOk =
    hasRustc && ((rustcMajor > msrvMajor) || (rustcMajor == msrvMajor && rustcMinor >= msrvMinor));
in
assert pkgs.lib.assertMsg msrvOk
  "sysdhardener: host nixpkgs rustc is ${rustcVersion}, but the workspace requires MSRV ${toString msrvMajor}.${toString msrvMinor}. Use the flake (nix develop) which pins nixpkgs to a release that ships rustc >=1.85, or override `pkgs` with a newer nixpkgs attribute path.";
pkgs.mkShell {
  packages = dependencies;
  shellHook = ''
    export SYSDHARDENER_DEV_ENV=non-flake
    echo "sysdhardener non-flake shell: rustc=${rustcVersion} (MSRV ${toString msrvMajor}.${toString msrvMinor})"
  '';
}
