# ssk's remote revoke snippet (MIT, like the rest of ssk). Removes every line of the
# user's authorized_keys that carries the key blob (second field) of the line read
# from stdin, so a key installed by hand with another comment or with options is
# still found.
#
# The three AUTH_KEY_FILE selection lines are copied from contrib/ssh-copy-id in
# OpenSSH portable (BSD-2-Clause; see install_snippet.sh and THIRD_PARTY_LICENSES.md)
# so install and revoke always agree on which file to touch.
#
# Rules for this file (enforced by tests in revoke.rs):
#   * comment lines are stripped before sending; no other line may contain #
#   * no single quotes anywhere below: the whole thing is sent as  exec sh -c '...'
#   * lines are joined with single spaces, so every statement ends in ; or && or ||
#
# Exit codes: 0 removed, 3 not present (no file, or no line with that blob), 4 removed but the SELinux relabel (restorecon) failed, 1 error.
cd;
umask 077;
AUTH_KEY_FILE=.ssh/authorized_keys;
[ -f /etc/openwrt_release ] && { [ "$LOGNAME" = "root" ] || [ "$(id -u)" = "0" ]; } && AUTH_KEY_FILE=/etc/dropbear/authorized_keys;
[ "`uname -s`" = "Haiku" ] && AUTH_KEY_FILE=config/settings/ssh/authorized_keys;
IFS= read -r k || exit 1;
set -f;
set -- $k;
b="$2";
[ -n "$b" ] || exit 1;
[ -f "${AUTH_KEY_FILE}" ] || exit 3;
grep -qF -- " $b" "${AUTH_KEY_FILE}" || exit 3;
TMP="${AUTH_KEY_FILE}.ssk.$$";
{ grep -vF -- " $b" "${AUTH_KEY_FILE}" > "${TMP}" || [ "$?" -eq 1 ]; } && mv -f "${TMP}" "${AUTH_KEY_FILE}" || { rm -f "${TMP}"; exit 1; };
if type restorecon >/dev/null 2>&1; then restorecon -F "${AUTH_KEY_FILE}" || exit 4; fi;
exit 0
