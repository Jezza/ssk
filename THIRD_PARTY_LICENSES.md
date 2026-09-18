# Third-party licences

## Remote install snippet (`src/ssh/install_snippet.sh`)

Vendored from OpenSSH portable, `contrib/ssh-copy-id`, as shipped in
OpenSSH 10.3p1 (Debian package `openssh-client`). One line was changed:
the unconditional `cat >> "${AUTH_KEY_FILE}"` became a read-one-line,
`grep -qxF`-then-append so that re-running never duplicates a key.

Licensed under the BSD 2-Clause licence:

```
Copyright (c) 1999-2025 Philip Hands <phil@hands.com>
              2025 Denis Ovsienko <denis@ovsienko.info>
              2024 Frank Fischer <f.fischer@freifunk-nordhessen.de>
              2021 Carlos Rodríguez Gili <carlos.rodriguez-gili@upc.edu>
              2020 Matthias Blümel <blaimi@blaimi.de>
              2017 Sebastien Boyron <seb@boyron.eu>
              2013 Martin Kletzander <mkletzan@redhat.com>
              2010 Adeodato =?iso-8859-1?Q?Sim=F3?= <asp16@alu.ua.es>
              2010 Eric Moret
              2009 Xr <xr@i-jeuxvideo.com>
              2007 Justin Pryzby <justinpryzby@users.sourceforge.net>
              2004 Reini Urban <rurban@x-ray.at>
              2003 Colin Watson <cjwatson@debian.org>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
