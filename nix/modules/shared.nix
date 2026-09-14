{ lib, pkgs, serverPackage }:
let
  inherit (lib) mkOption types;
  safePairingBasename = value:
    value != "."
    && value != ".."
    && value != "allowlist.json"
    && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" value != null;
  pairingBasenameType = types.nullOr (types.addCheck types.str safePairingBasename);
  nonzeroPortType = types.addCheck types.port (value: value != 0);

  options = {
    enable = lib.mkEnableOption "Pi Messaging Relay server";
    package = mkOption {
      type = types.package;
      default = serverPackage;
      defaultText = lib.literalExpression "inputs.pi-messaging-relay.packages.${pkgs.system}.pi-messaging-relay-server";
      description = "Relay server package.";
    };
    host = mkOption {
      type = types.enum [ "127.0.0.1" "::1" ];
      default = "127.0.0.1";
      description = "Loopback address on which the relay listens.";
    };
    port = mkOption {
      type = nonzeroPortType;
      default = 43127;
      description = "Nonzero relay listener port.";
    };
    pairingCodeFile = mkOption {
      type = pairingBasenameType;
      default = null;
      description = "Optional safe direct-child basename for one startup pairing code.";
    };
  };

  renderListener = host: port:
    if host == "::1" then "[::1]:${toString port}" else "127.0.0.1:${toString port}";

  makeLauncher = cfg:
    let
      argv = [
        "${cfg.package}/bin/pi-messaging-relay-server"
        "--listen"
        (renderListener cfg.host cfg.port)
        "--state-dir"
      ];
      pairingArg = lib.optionalString (cfg.pairingCodeFile != null) ''
        argv+=(--pairing-code-file "$STATE_DIRECTORY/${cfg.pairingCodeFile}")
      '';
    in pkgs.writeShellScript "pi-messaging-relay-launcher" ''
      set -eu
      if [ -z "''${STATE_DIRECTORY:-}" ]; then
        printf '%s\n' '{"level":"error","event":"server_failed","reason":"STATE_DIRECTORY is not set"}' >&2
        exit 1
      fi
      argv=(${lib.escapeShellArgs argv} "$STATE_DIRECTORY")
      ${pairingArg}
      exec "''${argv[@]}"
    '';
in {
  inherit options renderListener makeLauncher safePairingBasename;
}
