{
  description = "A basic flake to help develop treeland";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nix-filter.url = "github:numtide/nix-filter";
    treeland-protocols = {
      url = "github:linuxdeepin/treeland-protocols";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        nix-filter.follows = "nix-filter";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs = { self, nixpkgs, flake-utils, nix-filter, treeland-protocols }@input:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "riscv64-linux" ]
      (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          ddm = pkgs.qt6Packages.callPackage ./nix {
            nix-filter = nix-filter.lib;
            treeland-protocols = treeland-protocols.packages.${system}.default;
          };
        in
        {
          packages = {
            default = ddm;
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = [
              self.packages.${system}.default
            ];

            shellHook =
              let
                makeQtpluginPath = pkgs.lib.makeSearchPathOutput "out" pkgs.qt6.qtbase.qtPluginPrefix;
                makeQmlpluginPath = pkgs.lib.makeSearchPathOutput "out" pkgs.qt6.qtbase.qtQmlPrefix;
              in
              ''
                #export WAYLAND_DEBUG=1
                export QT_PLUGIN_PATH=${makeQtpluginPath (with pkgs.qt6; [ qtbase qtdeclarative qtquick3d qtimageformats qtwayland qt5compat qtsvg ])}
                export QML2_IMPORT_PATH=${makeQmlpluginPath (with pkgs.qt6; [ qtdeclarative qtquick3d qt5compat ]
                                                            ++ [ dde-nixos.packages.${system}.qt6.dtkdeclarative ] )}
                export QML_IMPORT_PATH=$QML2_IMPORT_PATH
              '';
          };
        }
      );
}
