# sc-remote

`sc-remote` is a source-aware SSH fleet CLI for humans and coding agents. It
keeps host discovery, direct routes, and bastion routes in one portable fleet
file while leaving private keys in SSH's normal local configuration.

It supports local-only state or a private Git repository as a synchronized
backend. The tool itself is safe to share publicly; your fleet data stays in
the backend you choose.

## Install

```bash
python3 -m pip install --user git+https://github.com/justcarlson/sc-remote.git
# or
uv tool install git+https://github.com/justcarlson/sc-remote.git
```

Python 3.10+, OpenSSH, and Git are the only runtime requirements.

## Start a fleet

```bash
sc-remote init --source laptop --role workstation
sc-remote host add server --endpoint admin@server.example.com --role app-server
sc-remote list
sc-remote check server
sc-remote run server -- uname -a
```

`host add` makes the host directly reachable from the current source unless
`--no-direct` is supplied. Add a route from another source with
`--direct-from SOURCE`; repeat the option for multiple sources.

Remove a host and all direct-route references:

```bash
sc-remote host remove server
```

Local targets and active bastions are protected from accidental removal.

## Synchronize through a remote backend

Use a **private, empty Git repository** for personal fleet data:

```bash
sc-remote backend set git@github.com:YOUR_USER/YOUR_PRIVATE_FLEET.git
sc-remote sync
```

Once configured, `host add`, `host remove`, `source add`, and `source remove`
pull the latest state, apply one validated change, commit it, and push it. Use
`--no-sync` to make a local pending change and `sc-remote sync` later.

On another machine:

```bash
sc-remote backend set git@github.com:YOUR_USER/YOUR_PRIVATE_FLEET.git
sc-remote sync
sc-remote source
sc-remote list
```

The backend can be GitHub, GitLab, Forgejo, a bare repository over SSH, or any
other Git remote. Authentication is delegated to Git/SSH; tokens and private
keys are never copied into fleet data.

## Source and route management

Each machine that runs the tool has a source profile. Hostname detection picks
the profile automatically; `SC_REMOTE_SOURCE` or global `--source` can override
it.

```bash
sc-remote source add bastion \
  --role agent-bastion \
  --local-target bastion \
  --detect-hostname bastion-01

sc-remote host add db --endpoint ops@db.internal --direct-from bastion
sc-remote source route-add laptop db --endpoint db-via-vpn
sc-remote source route-remove laptop db
```

Set a fallback bastion when one source should broker otherwise unreachable
targets through another source:

```bash
sc-remote source set-bastion laptop bastion
```

Routes are one of:

- `local`: target is this source's local target;
- `direct`: this source can SSH to the target;
- `broker`: `sc-remote` asks a directly reachable bastion to run the command;
- `unavailable`: no permitted route exists.

## Agent-friendly commands

```bash
sc-remote source
sc-remote list --json
sc-remote resolve server --json
sc-remote check server --timeout 8
sc-remote run server -- command arg
sc-remote shell server
sc-remote herdr server --session agents
sc-remote sync --json
```

`check` and `run` use batch-mode SSH, bounded connect timeouts, and a
source-specific known-hosts file. `shell` and `herdr` remain interactive.

## Data locations

The defaults follow XDG directories:

- settings: `$XDG_CONFIG_HOME/sc-remote/config.json`
- local fleet: `$XDG_DATA_HOME/sc-remote/fleet.json`
- backend checkout: `$XDG_STATE_HOME/sc-remote/backend`
- known hosts: `$XDG_STATE_HOME/sc-remote/known_hosts.<source>`

Override fleet state with `SC_REMOTE_FLEET`. Override source detection with
`SC_REMOTE_SOURCE`. Tests and temporary callers can override all XDG roots.

## Security model

- Fleet state accepts endpoints and metadata, not private-key material.
- Secret-like field names and private-key payloads are rejected before writes.
- SSH credentials stay in `ssh-agent`, `~/.ssh/config`, hardware tokens, or the
  platform's credential manager.
- Git backend credentials stay in Git/SSH's credential machinery.
- Backend checkouts and known-hosts files live outside this source repository.
- The repository ignores common key, token, environment, and fleet-state files.

Endpoints and hostnames can still be sensitive infrastructure metadata. Keep a
personal fleet backend private even though this tool is public.

See [SECURITY.md](SECURITY.md) for reporting and hardening guidance.
