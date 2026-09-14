{ pkgs, self }:
pkgs.testers.runNixOSTest {
  name = "pi-messaging-relay-nixos-runtime";
  nodes = {
    machine = { ... }: {
      imports = [ self.nixosModules.pi-messaging-relay ];
      services.pi-messaging-relay = {
        enable = true;
        host = "::1";
        port = 43127;
      };
      specialisation.stale.configuration.services.pi-messaging-relay.pairingCodeFile = "stale-code";
      specialisation.fresh.configuration.services.pi-messaging-relay.pairingCodeFile = "fresh-code";
    };
    ipv4 = { ... }: {
      imports = [ self.nixosModules.pi-messaging-relay ];
      services.pi-messaging-relay = {
        enable = true;
        host = "127.0.0.1";
        port = 43127;
      };
    };
  };
  testScript = ''
    start_all()

    ipv4.wait_for_unit("pi-messaging-relay.service")
    ipv4.wait_until_succeeds("journalctl -u pi-messaging-relay.service -o cat | grep '\"event\":\"server_ready\"'")
    ipv4_pid = ipv4.succeed("systemctl show -p MainPID --value pi-messaging-relay.service").strip()
    ipv4_argv = ipv4.succeed(f"tr '\\0' '\\n' </proc/{ipv4_pid}/cmdline")
    assert "--listen\n127.0.0.1:43127\n" in ipv4_argv
    assert "--state-dir\n/var/lib/pi-messaging-relay\n" in ipv4_argv
    ipv4.succeed("systemctl stop pi-messaging-relay.service")
    ipv4.succeed("journalctl -u pi-messaging-relay.service -o cat | grep '\"event\":\"server_stopped\"'")

    machine.wait_for_unit("pi-messaging-relay.service")
    machine.wait_until_succeeds("journalctl -u pi-messaging-relay.service -o cat | grep '\"event\":\"server_ready\"'")
    machine.succeed("test $(stat -c %a /var/lib/pi-messaging-relay) = 700")
    machine.succeed("test $(stat -c %U /var/lib/pi-messaging-relay) = pi-messaging-relay")
    machine.succeed("test $(systemctl show -p User --value pi-messaging-relay.service) = pi-messaging-relay")
    machine.succeed("test $(systemctl show -p Group --value pi-messaging-relay.service) = pi-messaging-relay")
    machine.succeed("test $(systemctl show -p DynamicUser --value pi-messaging-relay.service) = no")
    pid = machine.succeed("systemctl show -p MainPID --value pi-messaging-relay.service").strip()
    argv = machine.succeed(f"tr '\\0' '\\n' </proc/{pid}/cmdline")
    assert "--listen\n[::1]:43127\n" in argv
    assert "--state-dir\n/var/lib/pi-messaging-relay\n" in argv

    machine.succeed("systemctl restart pi-messaging-relay.service")
    machine.wait_until_succeeds("test $(journalctl -u pi-messaging-relay.service -o cat | grep -c '\"event\":\"server_ready\"') -ge 2")
    machine.succeed("systemctl stop pi-messaging-relay.service")
    machine.succeed("journalctl -u pi-messaging-relay.service -o cat | grep '\"event\":\"server_stopped\"'")

    fresh_system = machine.succeed("readlink -f /run/current-system/specialisation/fresh").strip()
    machine.succeed("printf fixture-secret-never-log >/var/lib/pi-messaging-relay/stale-code")
    machine.succeed("chown pi-messaging-relay:pi-messaging-relay /var/lib/pi-messaging-relay/stale-code && chmod 600 /var/lib/pi-messaging-relay/stale-code")
    machine.succeed("/run/current-system/specialisation/stale/bin/switch-to-configuration test")
    machine.succeed("systemctl start pi-messaging-relay.service || true")
    machine.wait_until_succeeds("systemctl is-failed pi-messaging-relay.service", timeout=30)
    machine.succeed("test $(cat /var/lib/pi-messaging-relay/stale-code) = fixture-secret-never-log")
    machine.succeed("test $(systemctl show -p Result --value pi-messaging-relay.service) = start-limit-hit")
    journal = machine.succeed("journalctl -u pi-messaging-relay.service -o cat")
    assert "file exists" in journal
    assert "fixture-secret-never-log" not in journal

    machine.succeed("systemctl reset-failed pi-messaging-relay.service")
    machine.succeed(f"{fresh_system}/bin/switch-to-configuration test")
    machine.succeed("systemctl start pi-messaging-relay.service")
    machine.wait_for_unit("pi-messaging-relay.service")
    machine.wait_until_succeeds("journalctl -u pi-messaging-relay.service -o cat | tail -n 20 | grep '\"event\":\"server_ready\"'")
    machine.succeed("test -f /var/lib/pi-messaging-relay/stale-code")
    machine.succeed("test -f /var/lib/pi-messaging-relay/fresh-code")
  '';
}
