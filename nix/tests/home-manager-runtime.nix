{ pkgs, self, home-manager }:
pkgs.testers.runNixOSTest {
  name = "pi-messaging-relay-home-manager-runtime";
  nodes.machine = { ... }: {
    imports = [ home-manager.nixosModules.home-manager ];
    users.users = {
      relayv4 = {
        isNormalUser = true;
        uid = 1000;
      };
      relayv6 = {
        isNormalUser = true;
        uid = 1001;
      };
    };
    home-manager.useGlobalPkgs = true;
    home-manager.users = {
      relayv4 = {
        imports = [ self.homeManagerModules.pi-messaging-relay ];
        home.stateVersion = "26.11";
        services.pi-messaging-relay = {
          enable = true;
          host = "127.0.0.1";
          port = 43127;
        };
      };
      relayv6 = {
        imports = [ self.homeManagerModules.pi-messaging-relay ];
        home.stateVersion = "26.11";
        services.pi-messaging-relay = {
          enable = true;
          host = "::1";
          port = 43127;
        };
      };
    };
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("home-manager-relayv4.service")
    machine.wait_for_unit("home-manager-relayv6.service")
    machine.fail("test -e /var/lib/systemd/linger/relayv4")
    machine.fail("test -e /var/lib/systemd/linger/relayv6")
    machine.succeed("systemctl start user@1000.service user@1001.service")
    machine.wait_for_unit("user@1000.service")
    machine.wait_for_unit("user@1001.service")

    def assert_user_service(user, uid, listener):
        userctl = f"runuser -u {user} -- env XDG_RUNTIME_DIR=/run/user/{uid} systemctl --user"
        journal = f"runuser -u {user} -- env XDG_RUNTIME_DIR=/run/user/{uid} journalctl --user -u pi-messaging-relay.service -o cat"
        state = f"/home/{user}/.local/state/pi-messaging-relay"
        machine.succeed(f"{userctl} restart pi-messaging-relay.service")
        machine.wait_until_succeeds(f"{userctl} is-active pi-messaging-relay.service")
        machine.wait_until_succeeds(f"{journal} | grep '\"event\":\"server_ready\"'")
        machine.succeed(f"{journal} | grep '\"auth\":\"off\"'")
        machine.succeed(f"test $(stat -c %a {state}) = 700")
        machine.succeed(f"test $(stat -c %U {state}) = {user}")
        fragment = machine.succeed(f"{userctl} cat pi-messaging-relay.service")
        assert "User=" not in fragment
        assert "Group=" not in fragment
        assert "DynamicUser=" not in fragment
        pid = machine.succeed(f"{userctl} show -p MainPID --value pi-messaging-relay.service").strip()
        argv = machine.succeed(f"tr '\\0' '\\n' </proc/{pid}/cmdline")
        assert f"--listen\n{listener}\n" in argv
        assert f"--state-dir\n{state}\n" in argv
        assert "--secret-file\n" not in argv
        machine.succeed(f"{userctl} restart pi-messaging-relay.service")
        machine.wait_until_succeeds(f"test $({journal} | grep -c '\"event\":\"server_ready\"') -ge 2")
        machine.succeed(f"{userctl} stop pi-messaging-relay.service")
        machine.succeed(f"{journal} | grep '\"event\":\"server_stopped\"'")

    assert_user_service("relayv4", 1000, "127.0.0.1:43127")
    assert_user_service("relayv6", 1001, "[::1]:43127")
    machine.fail("systemctl cat pi-messaging-relay.service")
    machine.fail("getent passwd pi-messaging-relay")
    machine.fail("getent group pi-messaging-relay")
  '';
}
