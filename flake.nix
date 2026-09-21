{
  description = "Development environment for the sysdhardener design package";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forSystem =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          bpfLinker = import ./nix/bpf-linker.nix { inherit pkgs; };
          dependencies = import ./nix/dependencies.nix { inherit pkgs bpfLinker; };
        in
        {
          devShells.default = pkgs.mkShell {
            packages = dependencies;
            shellHook = ''
              export SYSDHARDENER_DEV_ENV=flake
            '';
          };
        };
    in
    {
      devShells = builtins.listToAttrs (
        map (system: {
          name = system;
          value = (forSystem system).devShells;
        }) systems
      );
    };
}
