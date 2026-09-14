{ pkgs, self, serverPackage }:
let
  extensionTestSource = pkgs.buildNpmPackage {
    pname = "pi-messaging-relay-extension-test-source";
    version = "0.0.0";
    src = ../../extension;
    npmDepsHash = "sha256-1qDzypuYbL/YuGIvbbsxyuVgrvPJ26MlJTk6Nt5TFSU=";
    dontNpmBuild = true;
    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      cp -r . "$out/"
      runHook postInstall
    '';
  };
in
pkgs.testers.runNixOSTest {
  name = "pi-messaging-relay-extension-suite";
  nodes.machine = { ... }: {
    environment.systemPackages = [ pkgs.go pkgs.nodejs_24 pkgs.stdenv.cc ];
    virtualisation.memorySize = 2048;
  };
  testScript = ''
    machine.start()
    machine.succeed("cp -r ${self} /tmp/source && chmod -R u+w /tmp/source")
    machine.succeed("cp -r ${extensionTestSource}/node_modules /tmp/source/extension/node_modules")
    machine.succeed("cp -r ${serverPackage.goModules} /tmp/source/vendor")
    machine.succeed("cd /tmp/source/extension && GOFLAGS=-mod=vendor npm test", timeout=300)
  '';
}
