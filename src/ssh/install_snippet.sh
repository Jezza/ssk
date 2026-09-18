# Vendored from OpenSSH portable, contrib/ssh-copy-id (as shipped in OpenSSH
# 10.3p1), function installkeys_sh. See THIRD_PARTY_LICENSES.md.
#
# One change from upstream: the unconditional `cat >> "${AUTH_KEY_FILE}"` is
# replaced by "read one line; append only if grep -qxF does not find it", so a
# re-run never duplicates a key. Everything else is upstream, unescaped.
#
# Rules for this file (enforced by tests in install.rs):
#   * comment lines are stripped before sending; no other line may contain #
#   * no single quotes anywhere below: the whole thing is sent as  exec sh -c '...'
#   * lines are joined with single spaces, so every statement ends in ; or && or ||
#
# Copyright (c) 1999-2025 Philip Hands <phil@hands.com>
#               2025 Denis Ovsienko <denis@ovsienko.info>
#               2024 Frank Fischer <f.fischer@freifunk-nordhessen.de>
#               2021 Carlos Rodríguez Gili <carlos.rodriguez-gili@upc.edu>
#               2020 Matthias Blümel <blaimi@blaimi.de>
#               2017 Sebastien Boyron <seb@boyron.eu>
#               2013 Martin Kletzander <mkletzan@redhat.com>
#               2010 Adeodato =?iso-8859-1?Q?Sim=F3?= <asp16@alu.ua.es>
#               2010 Eric Moret
#               2009 Xr <xr@i-jeuxvideo.com>
#               2007 Justin Pryzby <justinpryzby@users.sourceforge.net>
#               2004 Reini Urban <rurban@x-ray.at>
#               2003 Colin Watson <cjwatson@debian.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
cd;
umask 077;
AUTH_KEY_FILE=.ssh/authorized_keys;
[ -f /etc/openwrt_release ] && { [ "$LOGNAME" = "root" ] || [ "$(id -u)" = "0" ]; } && AUTH_KEY_FILE=/etc/dropbear/authorized_keys;
[ "`uname -s`" = "Haiku" ] && AUTH_KEY_FILE=config/settings/ssh/authorized_keys;
AUTH_KEY_DIR=`dirname "${AUTH_KEY_FILE}"`;
mkdir -p "${AUTH_KEY_DIR}" &&
{ [ -z "`tail -1c "${AUTH_KEY_FILE}" 2>/dev/null`" ] || echo >> "${AUTH_KEY_FILE}" || exit 1; } &&
IFS= read -r k &&
{ grep -qxF -- "$k" "${AUTH_KEY_FILE}" 2>/dev/null || printf "%s\n" "$k" >> "${AUTH_KEY_FILE}"; } || exit 1;
if type restorecon >/dev/null 2>&1; then restorecon -F "${AUTH_KEY_DIR}" "${AUTH_KEY_FILE}"; fi
