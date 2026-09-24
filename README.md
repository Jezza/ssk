# ssk

ssk manages SSH identities. It generates keys, installs them on hosts, and
writes down where each key went, so that later on you can list, revoke and
rotate them without guessing which host still has what.

It is a front end for the OpenSSH tools you already have. Keys are generated
in-process in the same format `ssh-keygen` writes, installation runs the same
shell snippet `ssh-copy-id` runs, and the agent is driven through `ssh-add`.
What ssk adds is memory: a small TOML file next to your keys that records
when each identity was created and which `user@host:port` accepted it.

```
$ ssk new work
$ ssk copy work jezza@dev.example.com jezza@bastion.example.com:2222
$ ssk list
$ ssk rotate work
```

## Installing

```
cargo install --path .
```

Building needs Rust 1.88 or newer. At run time ssk needs `ssh` and `ssh-add`
on `PATH`. The remote end can be OpenSSH or dropbear; nothing needs to be
installed there.

Completions:

```
ssk completions zsh > ~/.zfunc/_ssk        # also bash, fish, elvish, powershell
```

## A tour

Create a key. The name is the file name under `~/.ssh`; the comment defaults
to `<name>@<hostname>`.

```
$ ssk new work
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
ok created identity work
  type         ed25519
  fingerprint  SHA256:w/aV5dga+tbOyKBacpg+JShtnm+ik/sXDfpmIWmOQvA
  private      /home/jezza/.ssh/work  (mode 0600, passphrase: yes)
  public       /home/jezza/.ssh/work.pub

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOQ4SH6HC94WlAy5MdzUCpB9/43Db0n5ezktTCtLzfd0 work@laptop

next: ssk copy work user@host   (or paste the public key above into GitHub, GitLab, ...)
```

ed25519 is the default. `-t rsa -b 4096` and `-t ecdsa -b 384` work as you
would expect. `--no-passphrase`, `-N <text>` and `--passphrase-stdin` are
there for scripts, and `--add` loads the new key into the agent straight away.

Install it. Each target is checked first, so re-running is harmless; the key
is only appended when the host does not accept it yet, and a second probe
confirms that it does afterwards.

```
$ ssk copy work jezza@dev.example.com --alias dev
added `Include ~/.ssh/ssk.d/*.conf` to /home/jezza/.ssh/config
ssh config written: /home/jezza/.ssh/ssk.d/work.conf
ok jezza@dev.example.com: installed and verified
```

Targets are `[user@]host[:port]`, or a `Host` alias from your own ssh config.
`-l` and `-p` set defaults for targets that leave the user or port out, and
`-o ProxyJump=bastion` style options are passed through to ssh. `ssk new`
takes `--copy TARGET` (and `-o` for it) too, for the common case of creating
a key and installing it in one go.

When a host has been reinstalled its key no longer matches `known_hosts`, and
ssh refuses to connect. If you know why the key changed,
`ssk copy --replace-host-key` removes the old entry (with `ssh-keygen -R`,
under the name and in the files `ssh -G` reports for the target) and
connects again, and ssh shows you the new fingerprint to accept. The old
entry is only removed when ssh actually reports a changed key.

Then ask what you have.

```
$ ssk list
 NAME   TYPE      FINGERPRINT            PASS   AGENT   HOSTS   COMMENT
 home   ed25519   SHA256:CUQeAsODVGyl…   no     yes     1       jezza@laptop
 work   ed25519   SHA256:w/aV5dga+tbO…   yes    yes     2       work@laptop

$ ssk hosts
 HOST                             ALIAS   home   work
 jezza@bastion.example.com:2222   -       -      ✓
 jezza@dev.example.com            dev     -      ✓
 nas.lan                          nas     ✓      -

$ ssk show work
work
  type         ed25519
  fingerprint  SHA256:w/aV5dga+tbOyKBacpg+JShtnm+ik/sXDfpmIWmOQvA
  comment      work@laptop
  passphrase   yes
  in agent     yes
  private      /home/jezza/.ssh/work  (mode 0600)
  public       /home/jezza/.ssh/work.pub  (mode 0644)
  created      2026-09-01T08:03:17Z
  hosts
    jezza@dev.example.com        alias dev              installed 2026-09-01T08:04:55Z
    jezza@bastion.example.com:2222 alias bastion.example.com installed 2026-09-03T14:20:09Z
  ssh config   /home/jezza/.ssh/ssk.d/work.conf

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOQ4SH6HC94WlAy5MdzUCpB9/43Db0n5ezktTCtLzfd0 work@laptop
```

`ssk show work --pub` prints the public key line alone and `--fingerprint`
the fingerprint alone, for piping. Keys that were not made by ssk appear in
`list` and `show` as well; they can be copied and rotated like any other, they
just have no creation time until ssk records something about them.

## What ssk writes, and where

- `~/.ssh/<name>` and `~/.ssh/<name>.pub`, mode 0600 and 0644. The identity
  name is the file name, so it follows file name rules: letters, digits,
  `.`, `_` and `-`, not starting with a dot, not ending in `.pub`, and not one
  of the names ssh already uses (`config`, `known_hosts`, `authorized_keys`
  and so on).
- `~/.ssh/ssk.toml`, mode 0600: for each identity, when it was created and a
  list of deployments (`host`, `user`, `port`, `alias`, `installed`).
- `~/.ssh/ssk.d/<name>.conf`, one per identity with deployments: a generated
  `Host` block per deployment with `IdentityFile` and `IdentitiesOnly yes`, so
  `ssh dev` picks the right key without you editing anything. These files are
  rewritten on every `copy`, `revoke` and `rename`; do not edit them.
- A single line, `Include ~/.ssh/ssk.d/*.conf`, at the top of `~/.ssh/config`.
  That is the only change ssk ever makes to your own config. Everything below
  it is preserved byte for byte, and if `config` is a symlink into a dotfiles
  repository ssk writes through the link rather than replacing it.

Set `write_ssh_config = false` in the config file, or pass `--no-config`, if
you would rather ssk left ssh config alone.

A different directory can be managed with `--ssh-dir` or `SSK_SSH_DIR`.

## Lifecycle

`ssk add [NAME...]` loads identities into ssh-agent through `ssh-add`, all of
them when no names are given.

`ssk rm NAME` deletes the key pair, its `ssk.d` file and its `ssk.toml` entry,
and drops it from the agent if it was loaded. Remote hosts are not touched; if
the identity is still recorded on any, ssk says so and points at `revoke`.

`ssk rename OLD NEW` moves the key pair and everything ssk keeps about it.
Your own `~/.ssh/config` is never edited, but any line in it that names the
old path is reported so you can fix it.

`ssk revoke NAME TARGET...` removes the public key from each host's
`authorized_keys`, matching on the key blob so that a line installed by hand
with a different comment or with options in front is still found, then
confirms the key no longer authenticates and forgets the deployment.
`ssk revoke NAME --all` does that for every host `ssk.toml` lists.

`ssk rotate NAME` replaces a key everywhere it is installed:

1. generate `NAME.new`;
2. install it on every recorded host, logging in with the current key;
3. once every host accepts the new key, remove the current key from all of
   them, logging in with the new one;
4. rename `NAME` to `NAME.old` and `NAME.new` to `NAME`, update `ssk.toml`,
   and delete the old pair.

Step 3 does not start until step 2 has succeeded on every host, so a host
that is down leaves you with both keys working rather than neither. Running
`ssk rotate NAME` again resumes with the `NAME.new` that already exists. If
the old key is still accepted somewhere after step 3, it is kept as
`NAME.old` with its remaining deployments recorded, and ssk tells you to
`ssk revoke NAME.old --all && ssk rm NAME.old` once the host is reachable.
Anything outside `ssk.toml` that holds the old public key, such as GitHub,
has to be updated by hand; the new public key is printed for that purpose.

## doctor

`ssk doctor` checks the directory for the things that make ssh refuse to work
or that you would want to know about: directory and key permissions, a
private key with no `.pub`, a world-writable `.pub`, RSA keys under 3072
bits, DSA keys, legacy PEM keys, orphaned `.pub` files, the same key stored
under two names, `ssk.toml` entries whose key is gone, and generated `Host`
blocks that are not actually included from `config`.

```
$ ssk doctor
warn  weak-rsa         /home/jezza/.ssh/legacy: rsa 2048-bit key; 3072+ bits or ed25519 is recommended
warn  key-perms        /home/jezza/.ssh/old: private key is mode 0644; ssh refuses keys readable by others  [fixable]
warn  missing-pub      /home/jezza/.ssh/work: no .pub file next to the private key  [fixable]
next: ssk doctor --fix   (applies the fixable ones; only tightens, never deletes)
```

`--fix` applies the safe ones: tightening permissions, regenerating a missing
`.pub` from the private key, adding the `Include` line. Nothing is ever
deleted or loosened. The exit status is 1 while any warning remains, which
makes it usable from a login script.

## Configuration

`~/.config/ssk/config.toml` (or `$XDG_CONFIG_HOME/ssk/config.toml`, or
`$SSK_CONFIG`) holds defaults. Every key is optional:

```toml
ssh_dir = "~/.ssh"
default_type = "ed25519"            # ed25519 | rsa | ecdsa
rsa_bits = 4096                     # 2048 | 3072 | 4096
comment = "{identity}@{hostname}"   # variables: {identity} {hostname} {user}
add_to_agent = false                # `ssk new` runs ssh-add afterwards
write_ssh_config = true             # `ssk copy` writes ssk.d/<identity>.conf and the Include line
```

Each key can also be set in the environment as `SSK_SSH_DIR`,
`SSK_DEFAULT_TYPE`, `SSK_RSA_BITS`, `SSK_COMMENT`, `SSK_ADD_TO_AGENT` and
`SSK_WRITE_SSH_CONFIG`. Command-line flags win over the environment, which
wins over the file, which wins over the built-in defaults. `ssk config get`
shows the effective value of each key and where it came from; `ssk config
set`, `unset` and `edit` change the file, validating before writing and
leaving your comments in place. Unknown keys and bad values are errors, but
the `config` subcommands still work on a file ssk cannot load, so a typo can
be fixed with ssk itself.

## Scripting

`--dry-run` prints every ssh command that would run and every file that
would change, and then does nothing. `--yes` answers the confirmations. `-v`
echoes each `ssh` and `ssh-add` invocation as it runs, and `-vv` passes `-v`
on to ssh.

`--json` gives `list`, `show`, `doctor`, `hosts` and `config get` a
machine-readable form on stdout. Every optional field is present, as `null`
when it has no value.

Exit status is 0 on success, 1 when something failed or was refused (a host
that could not be reached, a confirmation answered no, a `doctor` warning),
and 2 for a usage error.

## How ssk talks to hosts

Checking whether a key is installed is a login attempt with that key and
nothing else: `ssh -i KEY -o IdentitiesOnly=yes -o
PreferredAuthentications=publickey HOST exit`. Exit status alone is not
trusted, because ssh still tries every `IdentityFile` your config matches for
that host after the `-i` key, and a generated `ssk.d` block for another
identity is exactly such a line. ssk runs the probe at `LogLevel=DEBUG1` and
only counts the key as installed when ssh names it in its `server accepts
key:` line. This is what lets `rotate` and `revoke --all` tell two of your own
keys on the same host apart.

Installing runs the shell snippet from OpenSSH's `ssh-copy-id`, vendored with
one change: the key line is appended only if `grep -qxF` does not already
find it, so re-running never duplicates it. Removing runs a small snippet of
ssk's own that filters `authorized_keys` by key blob and writes it back
atomically. Both are sent as `exec sh -c '...'` so the remote login shell
does not matter, and both handle OpenWrt's dropbear path and SELinux
relabelling the way `ssh-copy-id` does. Both steps pass `IdentitiesOnly=yes`
so that an agent holding many keys does not burn through `MaxAuthTries`
before the password prompt; `-o IdentitiesOnly=no` on the command line
overrides that. If the install login is refused anyway (typically a host with
passwords off whose only working key lives in ssh-agent), `copy` retries it
once with agent keys allowed, unless `-o` already set `IdentitiesOnly`.

## Licence

MIT. The remote install snippet and three lines of the revoke snippet come
from OpenSSH's `ssh-copy-id` under the BSD 2-Clause licence; see
`THIRD_PARTY_LICENSES.md`.
