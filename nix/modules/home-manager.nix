{ self }:
{ config, lib, pkgs, ... }:
let
  shared = import ./shared.nix {
    inherit lib pkgs;
    serverPackage = self.packages.${pkgs.system}.pi-messaging-relay-server;
  };
  cfg = config.services.pi-messaging-relay;
in {
  options.services.pi-messaging-relay = shared.options;

  config = lib.mkIf cfg.enable {
    systemd.user.services.pi-messaging-relay = {
      Unit.Description = "Pi Messaging Relay";
      Unit.StartLimitIntervalSec = 30;
      Unit.StartLimitBurst = 3;
      Install.WantedBy = [ "default.target" ];
      Service = {
        ExecStart = shared.makeLauncher cfg;
        StateDirectory = "pi-messaging-relay";
        StateDirectoryMode = "0700";
        Restart = "on-failure";
        RestartSec = "2s";
        UMask = "0077";
        NoNewPrivileges = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      };
    };
  };
}
