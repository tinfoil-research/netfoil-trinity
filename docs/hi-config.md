# netfoil-hi config

## Command Line

### --ip \<ip>
Set the IP to listen on. When running with systemd, [/packaging/systemd/netfoil.socket](/packaging/systemd/netfoil.socket) is used instead.

- *Required*: no
- *Default*: `192.168.122.1`

### --port \<port>
Set the port to listen on. When running with systemd, [/packaging/systemd/netfoil.socket](/packaging/systemd/netfoil.socket) is used instead.

- *Required*: no
- *Default*: `8080`

### --config-directory \<path>
Set the path to look for the config (`<CONFIG DIRECTORY>`).

- *Required*: no
- *Default*: `/etc/netfoil-hi`


## Config file
Located in `<CONFIG DIRECTORY>/config`.

### EnableDebian=
Enable Debian provider.

- *Required*: no
- *Default*: `false`
- *Example*: `EnableDebian=true`

### EnableGitHub=
Enable GitHub provider.

- *Required*: no
- *Default*: `false`
- *Example*: `EnableGitHub=true`

### EnableGo=
Enable Go provider.

- *Required*: no
- *Default*: `false`
- *Example*: `EnableGo=true`

## Config directory
The default config is located in [/packaging/config](/packaging/config). It should be placed in `<CONFIG DIRECTORY>`.

### config
Specified in the section above.

### providers/debian
List of Debian packages to allow.

Examples: `git` and `*`.

### providers/github
List of GitHub repos to allow.

Examples: `tinfoil-factory/netfoil` and `tinfoil-factory/*`.

### providers/go
List of Go packages to allow.

Examples: `golang.org/x/sys` and `golang.org/x/*`.

### generic/\<filename\>
List of generic URLs to allow.

File names is the domain followed by one or more HTTPS verbs, separated by `:`.
Examples: `github.com:GET`, `github.com:GET:PUT`.

File contents is a list of paths on the domain.
Examples: `/tinfoil-factory/netfoil` and `/*`.