{
  description = "pasa: a small password store";

  # Pinned by flake.lock (`nix flake update`). Unstable: pasa needs Rust 1.97.
  inputs.nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      fs = lib.fileset;
      each = lib.genAttrs [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      # Linux: window and clipboard libraries are dlopened or run by name: given by path.
      pasa = pkgs: gui: let linux = pkgs.stdenv.isLinux; in pkgs.rustPlatform.buildRustPackage {
        pname = "pasa";
        version = (lib.importTOML ./Cargo.toml).package.version;
        src = fs.toSource { root = ./.; fileset = fs.unions [ ./Cargo.toml ./Cargo.lock ./src ./kdbx2pasa ./apasa-jni ]; };
        cargoLock = { lockFile = ./Cargo.lock; allowBuiltinFetchGit = true; };
        buildFeatures = lib.optional gui "gui";
        doCheck = false;
        preBuild = "unset AWS_LC_SYS_USE_SYSTEM"; # aws-lc as Cargo.lock pins it, not nixpkgs' copy
        # CMake: AWS-LC. bindgen: V4L2 (camera) bindings.
        nativeBuildInputs = [ pkgs.makeWrapper pkgs.cmake ]
          ++ lib.optionals linux [ pkgs.pkg-config pkgs.rustPlatform.bindgenHook ]
          ++ lib.optional (gui && linux) pkgs.copyDesktopItems;
        dontUseCmakeConfigure = true;
        buildInputs = lib.optionals linux [ pkgs.udev pkgs.pcsclite ];
        desktopItems = lib.optional (gui && linux) (pkgs.makeDesktopItem {
          name = "pasa"; desktopName = "pasa"; exec = "pasa gui"; categories = [ "Utility" "Security" ];
        });
        postFixup = lib.optionalString linux (''
          wrapProgram $out/bin/pasa --suffix PATH : ${lib.makeBinPath [ pkgs.wl-clipboard pkgs.xclip pkgs.curl ]}
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
      # `nix run`: the window; `nix run . -- ARGS`: pasa ARGS.
      apps = each (system: let
        pkgs = nixpkgs.legacyPackages.${system};
        gui = pkgs.writeShellScript "pasa-gui" ''
          exec ${self.packages.${system}.pasa-gui}/bin/pasa "''${@:-gui}"
        '';
        app = { type = "app"; program = "${gui}"; meta.description = "pasa: the window"; };
      in { default = app; pasa-gui = app; });

      # NixOS: inputs.pasa.url = "github:cablab-ucf/pasa"; modules = [
      # pasa.nixosModules.default { programs.pasa.enable = true; } ]. No
      # `inputs.pasa.inputs.nixpkgs.follows`: pasa builds on its own pin.
      nixosModules.default = { config, lib, pkgs, ... }: let cfg = config.programs.pasa; in {
        options.programs.pasa = {
          enable = lib.mkEnableOption "pasa, with PC/SC for NFC readers and YubiKeys";
          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${pkgs.stdenv.hostPlatform.system}.pasa-gui;
            description = "pasa-gui (the window) or pasa-cli.";
          };
          update = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = ''
              Daily, rebuild with pasa's newest main: system.autoUpgrade on the
              flake system.autoUpgrade.flake names (default /etc/nixos), whose
              input `pasa` alone is updated.
            '';
          };
          serve = lib.mkEnableOption "`pasa serve` as each user's service, seeing only ~/.pasa/store/v and ~/.pasa/net";
        };
        config = lib.mkIf cfg.enable (lib.mkMerge [
          {
            environment.systemPackages = [ cfg.package ];
            services.pcscd.enable = lib.mkDefault true;
          }
          (lib.mkIf cfg.update {
            system.autoUpgrade = {
              enable = true;
              flake = lib.mkDefault "/etc/nixos";
              flags = [ "--update-input" "pasa" ];
              dates = lib.mkDefault "daily";
            };
          })
          (lib.mkIf cfg.serve {
            systemd.user.services.pasa-serve = {
              description = "pasa serve";
              wantedBy = [ "default.target" ];
              unitConfig.ConditionPathExists = "%h/.pasa/net/peers";
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/pasa serve";
                Restart = "on-failure";
                RestartSec = 30;
                NoNewPrivileges = true;
                PrivateTmp = true;
                ProtectSystem = "strict";
                ProtectHome = "tmpfs";
                BindPaths = [ "%h/.pasa/store/v" "%h/.pasa/net" ];
              };
            };
          })
        ]);
      };
    };
}
