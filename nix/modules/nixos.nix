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
    users.groups.pi-messaging-relay = { };
    users.users.pi-messaging-relay = {
      isSystemUser = true;
      group = "pi-messaging-relay";
    };

    systemd.services.pi-messaging-relay = {
      description = "Pi Messaging Relay";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      startLimitIntervalSec = 30;
      startLimitBurst = 3;
      serviceConfig = {
        ExecStart = shared.makeLauncher cfg;
        User = "pi-messaging-relay";
        Group = "pi-messaging-relay";
        DynamicUser = false;
        StateDirectory = "pi-messaging-relay";
        StateDirectoryMode = "0700";
        Restart = "on-failure";
        RestartSec = "2s";
        UMask = "0077";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
