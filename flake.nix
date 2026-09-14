{
  description = "Reproducible Pi Messaging Relay packages and service modules";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/209c4430f3b76831d9d436c7158d5712a210f9b2";
    home-manager = {
      url = "github:nix-community/home-manager/cd1c9e552f41894aeb5cc5cb353d5a1d61550357";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ self, nixpkgs, home-manager }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          server = pkgs.buildGoModule {
            pname = "pi-messaging-relay-server";
            version = "0.0.0";
            src = ./.;
            vendorHash = "sha256-Zf6YlIt4EsDqBtxoUj7DshbVJ9a8RNGnqOjPAMgVoVo=";
            subPackages = [ "cmd/pi-messaging-relay-server" ];
            # The Nix sandbox presents / as uid 65534, which the relay correctly
            # rejects as an untrusted state ancestor. Compile tests here; the
            # complete suite runs in the go-suite VM with normal uid-0 root.
            checkPhase = ''
              runHook preCheck
              go test ./... -run '^$'
              runHook postCheck
            '';
          };
          extension = pkgs.buildNpmPackage {
            pname = "pi-messaging-relay-extension";
            version = "0.0.0";
            src = ./extension;
            npmDepsHash = "sha256-1qDzypuYbL/YuGIvbbsxyuVgrvPJ26MlJTk6Nt5TFSU=";
            dontNpmBuild = true;
            installPhase = ''
              runHook preInstall
              mkdir -p "$out"
              cp package.json index.ts "$out/"
              cp -r internal node_modules "$out/"
              runHook postInstall
            '';
          };
        in {
          pi-messaging-relay-extension = extension;
          pi-messaging-relay-server = server;
          default = server;
        });

      nixosModules = rec {
        pi-messaging-relay = import ./nix/modules/nixos.nix { inherit self; };
        default = pi-messaging-relay;
      };

      homeManagerModules = rec {
        pi-messaging-relay = import ./nix/modules/home-manager.nix { inherit self; };
        default = pi-messaging-relay;
      };

      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          packages = self.packages.${system};
          serverSmoke = import ./nix/tests/server-smoke.nix {
            inherit pkgs;
            serverPackage = packages.pi-messaging-relay-server;
          };
          extensionLoad = pkgs.runCommand "pi-messaging-relay-extension-load" {
            nativeBuildInputs = [ pkgs.coreutils pkgs.jq pkgs.pi-coding-agent ];
          } ''
            root="$TMPDIR/isolated"
            mkdir -p "$root/home" "$root/config" "$root/cache" "$root/state" "$root/pi-agent"
            printf '%s\n' '{"id":"commands","type":"get_commands"}' |
              env -i \
                HOME="$root/home" \
                XDG_CONFIG_HOME="$root/config" \
                XDG_CACHE_HOME="$root/cache" \
                XDG_STATE_HOME="$root/state" \
                PI_CODING_AGENT_DIR="$root/pi-agent" \
                PI_OFFLINE=1 \
                ${pkgs.coreutils}/bin/timeout --signal=TERM 20s \
                ${pkgs.pi-coding-agent}/bin/pi \
                  --mode rpc --no-session --no-extensions \
                  -e ${packages.pi-messaging-relay-extension}/ >stdout 2>stderr
            ${pkgs.jq}/bin/jq -e --arg root '${packages.pi-messaging-relay-extension}/' '
              .id == "commands" and .command == "get_commands" and .success == true and
              any(.data.commands[];
                .name == "relay-pair" and .source == "extension" and
                (.sourceInfo.path | startswith($root)))
            ' stdout
            ! grep -Ei 'extension.*(error|failed)|cannot find module' stderr
            ${pkgs.jq}/bin/jq -s -e '
              length == 2 and
              .[0].level == "info" and .[0].event == "relay_session_started" and .[0].result == "started" and
              .[1].level == "info" and .[1].event == "relay_session_stopped" and .[1].result == "graceful"
            ' stderr
            touch "$out"
          '';
          parity = import ./nix/tests/parity.nix {
            inherit pkgs self home-manager nixpkgs;
          };
          extensionTests = import ./nix/tests/extension-suite.nix {
            inherit pkgs self;
            serverPackage = packages.pi-messaging-relay-server;
          };
        in {
          inherit serverSmoke extensionLoad parity;
          extension-tests = extensionTests;
        } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          go-suite = import ./nix/tests/go-suite.nix {
            inherit pkgs self;
            serverPackage = packages.pi-messaging-relay-server;
          };
          nixos-module-runtime = import ./nix/tests/nixos-runtime.nix { inherit pkgs self; };
          home-manager-module-runtime = import ./nix/tests/home-manager-runtime.nix {
            inherit pkgs self home-manager;
          };
        });

      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.go pkgs.nodejs_24 ];
          };
        });
    };
}
