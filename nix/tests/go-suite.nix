{ pkgs, self, serverPackage }:
pkgs.testers.runNixOSTest {
  name = "pi-messaging-relay-go-suite";
  nodes.machine = { ... }: {
    environment.systemPackages = [ pkgs.go pkgs.stdenv.cc ];
    virtualisation.memorySize = 2048;
  };
  testScript = ''
    machine.start()
    machine.succeed("cp -r ${self} /tmp/source && chmod -R u+w /tmp/source")
    machine.succeed("cp -r ${serverPackage.goModules} /tmp/source/vendor")
    machine.succeed("cd /tmp/source && GOFLAGS=-mod=vendor go test ./...", timeout=180)
  '';
}
