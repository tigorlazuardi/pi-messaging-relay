{ pkgs, self, home-manager, nixpkgs }:
let
  lib = pkgs.lib;
  nixosFor = extra: nixpkgs.lib.nixosSystem {
    system = pkgs.system;
    modules = [
      self.nixosModules.pi-messaging-relay
      ({ lib, ... }: {
        options.programs.pi.settings.packages = lib.mkOption {
          type = lib.types.listOf lib.types.anything;
          default = [ ];
        };
        config = {
          boot.loader.grub.enable = false;
          fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
          system.stateVersion = "26.11";
          services.pi-messaging-relay.enable = true;
        };
      })
      extra
    ];
  };
  homeFor = extra: home-manager.lib.homeManagerConfiguration {
    inherit pkgs;
    modules = [
      self.homeManagerModules.pi-messaging-relay
      ({ lib, ... }: {
        options = {
          programs.pi.settings.packages = lib.mkOption {
            type = lib.types.listOf lib.types.anything;
            default = [ ];
          };
          services.nginx.enable = lib.mkOption {
            type = lib.types.bool;
            default = false;
          };
          networking.firewall.enable = lib.mkOption {
            type = lib.types.bool;
            default = true;
          };
        };
        config = {
          home.username = "relay-test";
          home.homeDirectory = "/home/relay-test";
          home.stateVersion = "26.11";
          services.pi-messaging-relay.enable = true;
        };
      })
      extra
    ];
  };
  nixos = nixosFor { };
  home = homeFor { };
  nixOptions = nixos.options.services.pi-messaging-relay;
  homeOptions = home.options.services.pi-messaging-relay;
  optionNames = [ "enable" "host" "package" "pairingCodeFile" "port" ];
  defaultsEqual = name:
    if name == "package"
    then nixOptions.${name}.default.drvPath == homeOptions.${name}.default.drvPath
    else nixOptions.${name}.default == homeOptions.${name}.default;
  invalidCases = [
    { host = "localhost"; }
    { port = 0; }
    { port = 65536; }
  ] ++ map (pairingCodeFile: { inherit pairingCodeFile; }) [
    "." ".." "allowlist.json" "../code" "dir/code" "white space" "quote\"" "percent%" "-leading" "tab\tname"
  ];
  nixosRejects = value: !(builtins.tryEval (nixosFor {
    services.pi-messaging-relay = value;
  }).config.system.build.toplevel.drvPath).success;
  homeRejects = value: !(builtins.tryEval (homeFor {
    services.pi-messaging-relay = value;
  }).activationPackage.drvPath).success;
  packages = self.packages.${pkgs.system};
in
assert builtins.attrNames packages == [ "default" "pi-messaging-relay-extension" "pi-messaging-relay-server" ];
assert packages.default.drvPath == packages.pi-messaging-relay-server.drvPath;
assert lib.length (lib.unique (map (name: packages.${name}.drvPath) (builtins.attrNames packages))) == 2;
# The exported rec bindings are exact aliases; evaluate both names through their public schema.
assert builtins.attrNames (nixosFor { imports = [ self.nixosModules.default ]; }).options.services.pi-messaging-relay == optionNames;
assert builtins.attrNames (home-manager.lib.homeManagerConfiguration {
  inherit pkgs;
  modules = [
    self.homeManagerModules.default
    ({ lib, ... }: {
      options = {
        programs.pi.settings.packages = lib.mkOption { type = lib.types.listOf lib.types.anything; default = [ ]; };
        services.nginx.enable = lib.mkOption { type = lib.types.bool; default = false; };
        networking.firewall.enable = lib.mkOption { type = lib.types.bool; default = true; };
      };
      config = {
        home.username = "alias-test";
        home.homeDirectory = "/home/alias-test";
        home.stateVersion = "26.11";
      };
    })
  ];
}).options.services.pi-messaging-relay == optionNames;
assert builtins.attrNames nixOptions == optionNames;
assert builtins.attrNames homeOptions == optionNames;
assert lib.all (name: nixOptions.${name}.type.description == homeOptions.${name}.type.description) optionNames;
assert lib.all defaultsEqual optionNames;
assert lib.all (value: nixosRejects value && homeRejects value) invalidCases;
assert nixos.config.programs.pi.settings.packages == [ ];
assert nixos.config.services.nginx.enable == false;
assert nixos.config.networking.firewall.enable == true;
assert !(nixos.config.systemd.user.services ? pi-messaging-relay);
assert home.config.programs.pi.settings.packages == [ ];
assert home.config.services.nginx.enable == false;
assert home.config.networking.firewall.enable == true;
assert !(home.config.systemd.user.services.pi-messaging-relay.Service ? User);
assert !(home.config.systemd.user.services.pi-messaging-relay.Service ? Group);
assert !(home.config.systemd.user.services.pi-messaging-relay.Service ? DynamicUser);
assert !(builtins.hasAttr "pi-messaging-relay" (home.config.systemd.services or { }));
pkgs.runCommand "pi-messaging-relay-module-parity" { } ''
  touch "$out"
''
