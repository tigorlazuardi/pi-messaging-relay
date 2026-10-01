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
        secretFile = "/var/lib/pi-messaging-relay/relay-secret";
      };
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

    # Auth-off node: no secretFile, no --secret-file argv, server_ready auth off.
    ipv4.wait_for_unit("pi-messaging-relay.service")
    ipv4.wait_until_succeeds("journalctl -u pi-messaging-relay.service -o cat | grep '\"event\":\"server_ready\"'")
    ipv4.succeed("journalctl -u pi-messaging-relay.service -o cat | grep '\"auth\":\"off\"'")
    ipv4_pid = ipv4.succeed("systemctl show -p MainPID --value pi-messaging-relay.service").strip()
    ipv4_argv = ipv4.succeed(f"tr '\\0' '\\n' </proc/{ipv4_pid}/cmdline")
    assert "--listen\n127.0.0.1:43127\n" in ipv4_argv
    assert "--state-dir\n/var/lib/pi-messaging-relay\n" in ipv4_argv
    assert "--secret-file\n" not in ipv4_argv
    ipv4.succeed("systemctl stop pi-messaging-relay.service")
    ipv4.succeed("journalctl -u pi-messaging-relay.service -o cat | grep '\"event\":\"server_stopped\"'")

    # Auth-on node: secret file missing at first boot must fail startup before
    # server_ready (a set-but-broken secret never degrades to auth-off).
    machine.wait_until_succeeds("systemctl is-failed pi-messaging-relay.service", timeout=30)
    machine.succeed("test $(systemctl show -p Result --value pi-messaging-relay.service) = start-limit-hit")
    machine.succeed("journalctl -u pi-messaging-relay.service -o cat | grep '\"event\":\"server_failed\"'")

    # Operator provisions the mode-0600 direct state-dir child and recovers.
    machine.succeed("install -d -m 700 /var/lib/pi-messaging-relay")
    machine.succeed("printf 'oracle-v2-shared-secret\\n' > /var/lib/pi-messaging-relay/relay-secret")
    machine.succeed("chown pi-messaging-relay:pi-messaging-relay /var/lib/pi-messaging-relay/relay-secret")
    machine.succeed("chmod 600 /var/lib/pi-messaging-relay/relay-secret")
    machine.succeed("systemctl reset-failed pi-messaging-relay.service")
    machine.succeed("systemctl start pi-messaging-relay.service")
    machine.wait_for_unit("pi-messaging-relay.service")
    machine.wait_until_succeeds("journalctl -u pi-messaging-relay.service -o cat | grep '\"event\":\"server_ready\"'")
    machine.succeed("journalctl -u pi-messaging-relay.service -o cat | grep '\"auth\":\"secret\"'")
    machine.succeed("test $(stat -c %a /var/lib/pi-messaging-relay) = 700")
    machine.succeed("test $(stat -c %U /var/lib/pi-messaging-relay) = pi-messaging-relay")
    machine.succeed("test $(stat -c %a /var/lib/pi-messaging-relay/relay-secret) = 600")
    machine.succeed("test $(systemctl show -p User --value pi-messaging-relay.service) = pi-messaging-relay")
    machine.succeed("test $(systemctl show -p Group --value pi-messaging-relay.service) = pi-messaging-relay")
    machine.succeed("test $(systemctl show -p DynamicUser --value pi-messaging-relay.service) = no")
    pid = machine.succeed("systemctl show -p MainPID --value pi-messaging-relay.service").strip()
    argv = machine.succeed(f"tr '\\0' '\\n' </proc/{pid}/cmdline")
    assert "--listen\n[::1]:43127\n" in argv
    assert "--state-dir\n/var/lib/pi-messaging-relay\n" in argv
    assert "--secret-file\n/var/lib/pi-messaging-relay/relay-secret\n" in argv

    # The secret value never leaks into the unit text or the journal; the
    # launcher carries only the host path (no Nix-store copy of the secret).
    machine.fail("systemctl cat pi-messaging-relay.service | grep -q oracle-v2-shared-secret")
    machine.fail("journalctl -u pi-messaging-relay.service -o cat | grep -q oracle-v2-shared-secret")

    # Restart-to-rotate seam: restart re-reads the secret and stays in auth secret.
    machine.succeed("systemctl restart pi-messaging-relay.service")
    machine.wait_until_succeeds("test $(journalctl -u pi-messaging-relay.service -o cat | grep -c '\"event\":\"server_ready\"') -ge 2")
    machine.succeed("journalctl -u pi-messaging-relay.service -o cat | tail -n 20 | grep '\"auth\":\"secret\"'")
    machine.succeed("systemctl stop pi-messaging-relay.service")
    machine.succeed("journalctl -u pi-messaging-relay.service -o cat | grep '\"event\":\"server_stopped\"'")
  '';
}
