# pcopy
pcopy is cross-machine clipboard that allows copying (`pcp < file.txt`) and pasting (`ppaste > file.txt`)
across different computers. Other users can be invited to join (`pcopy invite`), or simply join by specifying 
the hostname (`pcopy join`). Clipboards can have passwords, or they can be open for everyone.  

## Installation

tbd

## Usage
**To setup a new pcopy server**, run `sudo pcopy setup`. It'll walk you through a setup wizard. After that, you can run
the server via `sudo systemctl start pcopy` (or manually via `sudo -u pcopy pcopy serve`).

**To join an existing clipboard**, simple run `pcopy join <host>>`:
```
$ pcopy join pcopy.example.com
Successfully joined clipboard, config written to ~/.config/pcopy/default.conf

You may now use 'pcp' and 'ppaste'. See 'pcopy -h' for usage details.
To install pcopy on other computers, or join this clipboard, use 'pcopy invite' command.
```

More details can be found on the help page:
```
$ pcopy -help
Usage: pcopy COMMAND [OPTION..] [ARG..]

Client-side commands:
  join      Join a remote clipboard
  invite    Generate commands to invite others to join a clipboard
  copy      Read from STDIN and copy to remote clipboard
  paste     Write remote clipboard contents to STDOUT

Server-side commands:
  setup     Initial setup wizard for a new pcopy server
  serve     Start pcopy server
  keygen    Generate key for the server config

Try 'pcopy COMMAND -help' for more information.
```

## Inspired by
Thanks [nakabonne](https://github.com/nakabonne) for making [pbgopy](https://github.com/nakabonne/pbgopy). It inspired me to make pcopy. 

## License
Made by Philipp Heckel, distributed under the [Apache License 2.0](LICENSE).
