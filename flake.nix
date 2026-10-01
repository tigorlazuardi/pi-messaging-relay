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
          extensionOracle = pkgs.writeShellScript "pi-messaging-relay-extension-oracle" ''
            # writeShellScript does not inject strict mode; without errexit every
            # guardrail below (wait_ready timeout, auth greps, leak checks, mode
            # test, jq lifecycle) would be non-fatal. Note: errexit ignores the
            # exit status of !-prefixed commands, so negative greps use explicit
            # if/fail blocks instead of `! grep`.
            set -eu
            set -o pipefail

            root="$(mktemp -d)"
            mkdir -p "$root/home/.config/pi" "$root/cache" "$root/pi-agent"
            install -d -m 700 "$root/state" "$root/state-off"

            wait_ready() { # <stdout-file> <auth-mode> — bounded readiness wait
              i=0
              while [ "$i" -lt 100 ]; do
                if grep -q '"event":"server_ready"' "$1" && grep -q "\"auth\":\"$2\"" "$1"; then
                  return 0
                fi
                sleep 0.1
                i=$((i + 1))
              done
              echo "TRACE wait_ready timeout for $1 (auth $2)"
              echo '--- server stdout:'; cat "$1" || true
              echo '--- server stderr:'; cat "''${1%.out}.err" || true
              return 1
            }

            run_pi() { # <stdout-file> <stderr-file>
              printf '%s\n' '{"id":"commands","type":"get_commands"}' |
                env -i \
                  HOME="$root/home" \
                  XDG_CACHE_HOME="$root/cache" \
                  XDG_STATE_HOME="$root/state" \
                  PI_CODING_AGENT_DIR="$root/pi-agent" \
                  PI_OFFLINE=1 \
                  ${pkgs.coreutils}/bin/timeout --signal=TERM 30s \
                  ${pkgs.pi-coding-agent}/bin/pi \
                    --mode rpc --no-session --no-extensions \
                    -e ${packages.pi-messaging-relay-extension}/ >"$1" 2>"$2"
            }

            assert_no_match() { # <description> <files...> — fail fatally when the pattern matches
              desc="$1"; shift
              if grep -q "$@"; then
                echo "FAIL $desc"
                exit 1
              fi
            }

            assert_lifecycle() { # <stderr-file> — v2 session lifecycle: started, Bearer accepted, disconnected, stopped graceful
              ${pkgs.jq}/bin/jq -s -e '
                length == 4 and
                .[0].level == "info" and .[0].event == "relay_session_started" and .[0].result == "started" and
                .[1].level == "info" and .[1].event == "relay_auth_accepted" and .[1].result == "accepted" and
                .[2].level == "info" and .[2].event == "relay_session_disconnected" and .[2].result == "disconnected" and
                .[3].level == "info" and .[3].event == "relay_session_stopped" and .[3].result == "graceful"
              ' "$1"
            }

            # --- auth-on variant: server secret file, client config file, Bearer connect ---
            printf 'oracle-v2-shared-secret\n' >"$root/state/relay-secret"
            chmod 600 "$root/state/relay-secret"
            ${packages.pi-messaging-relay-server}/bin/pi-messaging-relay-server \
              --listen 127.0.0.1:45673 --state-dir "$root/state" \
              --secret-file "$root/state/relay-secret" >server-auth.out 2>server-auth.err &
            server_auth_pid=$!
            wait_ready server-auth.out secret
            install -m 600 /dev/null "$root/home/.config/pi/pi-messaging-relay.json"
            printf '{"url":"http://127.0.0.1:45673","secret":"oracle-v2-shared-secret"}\n' \
              >"$root/home/.config/pi/pi-messaging-relay.json"
            run_pi stdout stderr
            test "$(stat -c %a "$root/home/.config/pi/pi-messaging-relay.json")" = 600
            # Since #81 the extension's ctx.ui.setStatus calls surface as
            # extension_ui_request documents on stdout, interleaved with RPC
            # responses. jq -e on the raw stream keys off the LAST document
            # (a setStatus request), so the stream must be slurped and the
            # response document(s) selected explicitly. Assert: exactly one
            # response overall, it is the get_commands reply with success,
            # it exposes no relay-pair command, and setStatus requests only
            # ever use the extension's own statusKey.
            ${pkgs.jq}/bin/jq -s -e '
              ([.[] | select(.type == "response")] | length) == 1 and
              ([.[] | select(.type == "response" and
                  .id == "commands" and .command == "get_commands")] | length) == 1 and
              all(.[] | select(.type == "response" and .id == "commands");
                  .success == true and all(.data.commands[]?; .name != "relay-pair")) and
              all(.[] | select(.type == "extension_ui_request" and .method == "setStatus");
                  .statusKey == "pi-messaging-relay")
            ' stdout
            assert_lifecycle stderr
            assert_no_match 'extension errors in stderr' -Ei 'extension.*(error|failed)|cannot find module|relay_config_rejected' stderr
            grep -q '"event":"server_ready"' server-auth.out
            grep -q '"auth":"secret"' server-auth.out
            grep -q '"event":"auth_accepted"' server-auth.out
            assert_no_match 'secret leaked into output' 'oracle-v2-shared-secret' server-auth.out server-auth.err stdout stderr
            kill "$server_auth_pid"
            wait "$server_auth_pid"
            grep -q '"event":"server_stopped"' server-auth.out

            # --- auth-off variant: no secret file, unsigned upgrade still accepted ---
            ${packages.pi-messaging-relay-server}/bin/pi-messaging-relay-server \
              --listen 127.0.0.1:45674 --state-dir "$root/state-off" >server-off.out 2>server-off.err &
            server_off_pid=$!
            wait_ready server-off.out off
            printf '{"url":"http://127.0.0.1:45674"}\n' \
              >"$root/home/.config/pi/pi-messaging-relay.json"
            run_pi stdout-off stderr-off
            assert_lifecycle stderr-off
            assert_no_match 'extension errors in stderr-off' -Ei 'extension.*(error|failed)|cannot find module|relay_config_rejected' stderr-off
            grep -q '"auth":"off"' server-off.out
            grep -q '"event":"auth_accepted"' server-off.out
            kill "$server_off_pid"
            wait "$server_off_pid"
            grep -q '"event":"server_stopped"' server-off.out
          '';
          extensionLoad = pkgs.testers.runNixOSTest {
            name = "pi-messaging-relay-extension-load";
            nodes.machine = { ... }: {
              environment.systemPackages = [ pkgs.pi-coding-agent pkgs.jq ];
              # The oracle binds fixed ports 45673/45674; a leftover listener
              # from any earlier run must not silently poison this check.
              networking.firewall.enable = false;
            };
            testScript = ''
              machine.start()
              print(machine.succeed("${extensionOracle} 2>&1 || (echo ORACLE-FAILED; exit 1)"))
            '';
          };
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
