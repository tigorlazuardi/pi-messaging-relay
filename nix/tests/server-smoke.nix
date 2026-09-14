{ pkgs, serverPackage }:
pkgs.testers.runNixOSTest {
  name = "pi-messaging-relay-server-smoke";
  nodes.machine = { ... }: {
    environment.systemPackages = [ serverPackage ];
  };
  testScript = ''
    machine.start()
    for family, listener in (("ipv4", "127.0.0.1:0"), ("ipv6", "[::1]:0")):
        unit = f"pi-messaging-relay-smoke-{family}"
        state = f"/var/lib/{unit}"
        machine.succeed(f"install -d -m 700 {state}")
        machine.succeed(f"systemd-run --unit={unit} --property=Type=simple --property=TimeoutStopSec=10 ${serverPackage}/bin/pi-messaging-relay-server --listen '{listener}' --state-dir {state}")
        machine.wait_until_succeeds(f"journalctl -u {unit}.service -o cat | grep '\"event\":\"server_ready\"'")
        machine.succeed(f"systemctl stop {unit}.service")
        machine.wait_until_succeeds(f"journalctl -u {unit}.service -o cat | grep '\"event\":\"server_stopped\"'")
        machine.succeed(f"test $(systemctl show -p ExecMainStatus --value {unit}.service) = 0")
  '';
}
