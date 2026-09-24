"""Run as root, keep the operator's files in the operator's home.

Under `sudo netlab` the process is root, but config, captures and engagements
belong to the person who ran it -- not to root. These tests pin down that the
paths resolve to the SUDO_UID home and that files are handed back to them.
"""

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from netlab import config


class TestRealUserPaths(unittest.TestCase):
    def test_normal_run_uses_the_current_home(self):
        with patch("os.geteuid", return_value=1000):
            uid, gid, home = config.real_user()
        self.assertEqual(home, Path.home())

    def test_root_via_sudo_uses_the_operator_home(self):
        import pwd
        me = pwd.getpwuid(os.getuid())
        with patch("os.geteuid", return_value=0), \
                patch.dict(os.environ, {"SUDO_UID": str(me.pw_uid)}):
            uid, gid, home = config.real_user()
            self.assertEqual(uid, me.pw_uid)
            self.assertEqual(home, Path(me.pw_dir))
            # config/data resolve under the operator's home, not /root
            self.assertTrue(str(config.config_dir()).startswith(me.pw_dir))
            self.assertTrue(str(config.data_dir()).startswith(me.pw_dir))

    def test_root_without_sudo_uid_stays_root(self):
        # Root with no SUDO_UID (a real root login) just uses the current
        # identity -- it does not go hunting for another user.
        with patch("os.geteuid", return_value=0), \
                patch("os.getuid", return_value=0), \
                patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SUDO_UID", None)
            os.environ.pop("PKEXEC_UID", None)
            uid, gid, home = config.real_user()
        self.assertEqual(uid, 0)

    def test_xdg_env_still_wins(self):
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": "/tmp/xdgtest"}):
            self.assertEqual(config.config_dir(), Path("/tmp/xdgtest/netlab"))

    def test_own_is_a_noop_when_not_root(self):
        # Must never raise, and must not touch ownership as a normal user.
        with patch("os.geteuid", return_value=1000), \
                patch("os.chown") as chown:
            config._own(Path("/tmp"))
            chown.assert_not_called()


if __name__ == "__main__":
    unittest.main()
