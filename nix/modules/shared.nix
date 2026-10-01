{ lib, pkgs, serverPackage }:
let
  inherit (lib) mkOption types;
  nonzeroPortType = types.addCheck types.port (value: value != 0);
  # Guardrail (accepted auth v2, "Nix and secrets guardrail"): the option may name
  # only an absolute host path outside the world-readable Nix store. A store path
  # or a string with store context (a derivation secret) fails evaluation.
  hostSecretFileType = types.nullOr (types.addCheck types.str (value:
    lib.isString value
    && lib.hasPrefix "/" value
    && !lib.hasPrefix "/nix/store/" value
  ));

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
    secretFile = mkOption {
      type = hostSecretFileType;
      default = null;
      description = ''
        Optional absolute host path to the operator-owned server secret file,
        satisfying the server's --secret-file contract: a direct child of the
        state directory, mode 0600, 1-512 bytes after trimming. When set, the
        launcher passes --secret-file; when null, the server starts with
        authentication off. The path is passed through verbatim and never
        copied into or read from the Nix store; rotate by rewriting the file
        and restarting the service.
      '';
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
      secretArg = lib.optionalString (cfg.secretFile != null) ''
        argv+=(--secret-file ${lib.escapeShellArg cfg.secretFile})
      '';
    in pkgs.writeShellScript "pi-messaging-relay-launcher" ''
      set -eu
      if [ -z "''${STATE_DIRECTORY:-}" ]; then
        printf '%s\n' '{"level":"error","event":"server_failed","reason":"STATE_DIRECTORY is not set"}' >&2
        exit 1
      fi
      argv=(${lib.escapeShellArgs argv} "$STATE_DIRECTORY")
      ${secretArg}
      exec "''${argv[@]}"
    '';
in {
  inherit options renderListener makeLauncher hostSecretFileType;
}
