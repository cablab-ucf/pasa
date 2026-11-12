{
  description = "pasa: a small password store";

  # Pinned by flake.lock (`nix flake update`). Unstable: pasa needs Rust 1.97.
  inputs.nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      fs = lib.fileset;
      each = lib.genAttrs [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      # `gui`: also `pasa gui`. What a window and a clipboard need is dlopened or
      # run by name, so on Linux both are given by path.
      pasa = pkgs: gui: let linux = pkgs.stdenv.isLinux; in pkgs.rustPlatform.buildRustPackage {
        pname = "pasa";
        version = (lib.importTOML ./Cargo.toml).package.version;
        src = fs.toSource { root = ./.; fileset = fs.unions [ ./Cargo.toml ./Cargo.lock ./src ./kdbx2pasa ./apasa-jni ]; };
        cargoLock = { lockFile = ./Cargo.lock; allowBuiltinFetchGit = true; }; # irnet, pushir, pairir by commit
        buildFeatures = lib.optional gui "gui";
        doCheck = false;
        preBuild = "unset AWS_LC_SYS_USE_SYSTEM"; # aws-lc as Cargo.lock pins it, not nixpkgs' copy
        # CMake builds AWS-LC (security keys' key agreement), not pasa.
        # Linux: pkg-config finds libudev (security keys); bindgen, with its
        # libclang, writes V4L2's bindings (the camera) at build time.
        nativeBuildInputs = [ pkgs.makeWrapper pkgs.cmake ]
          ++ lib.optionals linux [ pkgs.pkg-config pkgs.rustPlatform.bindgenHook ]
          ++ lib.optional (gui && linux) pkgs.copyDesktopItems;
        dontUseCmakeConfigure = true;
        # libudev: security keys over USB; pcsc-lite: keys on NFC readers.
        buildInputs = lib.optionals linux [ pkgs.udev pkgs.pcsclite ];
        desktopItems = lib.optional (gui && linux) (pkgs.makeDesktopItem {
          name = "pasa"; desktopName = "pasa"; exec = "pasa gui"; categories = [ "Utility" "Security" ];
        });
        postFixup = lib.optionalString linux (''
          wrapProgram $out/bin/pasa --suffix PATH : ${lib.makeBinPath [ pkgs.wl-clipboard pkgs.xclip ]}
        '' + lib.optionalString gui ''
          patchelf --add-rpath ${lib.makeLibraryPath (with pkgs; [
            libGL libxkbcommon wayland xorg.libX11 xorg.libXcursor xorg.libXi xorg.libXrandr
          ])} $out/bin/.pasa-wrapped
        '');
        meta = { mainProgram = "pasa"; license = lib.licenses.gpl3Plus; };
      };
    in {
      packages = each (system: let pkgs = nixpkgs.legacyPackages.${system}; in rec {
        default = pasa-gui;
        pasa-gui = pasa pkgs true;   # cli, tui, gui
        pasa-cli = pasa pkgs false;  # cli, tui: no window libraries
      });
      # `nix run` (or .#pasa-gui): the window; with arguments, pasa itself
      # (`nix run . -- ls`).
      apps = each (system: let
        pkgs = nixpkgs.legacyPackages.${system};
        gui = pkgs.writeShellScript "pasa-gui" ''
          exec ${self.packages.${system}.pasa-gui}/bin/pasa "''${@:-gui}"
        '';
        app = { type = "app"; program = "${gui}"; meta.description = "pasa: the window"; };
      in { default = app; pasa-gui = app; });
    };
}
