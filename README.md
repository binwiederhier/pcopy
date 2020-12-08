# pcopy
pcopy is cross-machine clipboard that allows copying (`pcp < file.txt`) and pasting (`ppaste > file.txt`)
across different computers. Other users can be invited to join (`pcopy invite`), or simply join by specifying 
the hostname (`pcopy join`). Clipboards can have passwords, or they can be open for everyone.  

![Demo](assets/demo.gif)

## Installation
Binaries can be found on the [releases page](https://github.com/binwiederhier/pcopy/releases). Alternatively, for a quick install, run:
```bash
curl -sSL https://heckel.io:1986/install | sudo sh
```

Once you've installed pcopy, you may run `pcopy invite` to generate your own quick download links and quick join instructions.

## Usage
**To setup a new pcopy server**, run `sudo pcopy setup`. It'll walk you through a setup wizard. After that, you can run
the server via `sudo systemctl start pcopy` (or manually via `sudo -u pcopy pcopy serve`).

**To join an existing clipboard**, simple run `pcopy join <host>>`:
```bash
$ pcopy join pcopy.example.com
Successfully joined clipboard, config written to ~/.config/pcopy/default.conf

You may now use 'pcp' and 'ppaste'. See 'pcopy -h' for usage details.
To install pcopy on other computers, or join this clipboard, use 'pcopy invite' command.
```

**Now you can start copying and pasting** by using `pcp` (`pcopy copy`) and `ppaste` (`pcopy paste`). Any connected
client, regardless of what computer it's on, can copy/paste like this:

```bash
$ pcp < foo.txt            # Copies foo.txt to the default clipboard
$ pcp bar < bar.txt        # Copies bar.txt to the default clipboard as 'bar'
$ echo hi | pcp work:      # Copies 'hi' to the 'work' clipboard
$ echo ho | pcp work:bla   # Copies 'ho' to the 'work' clipboard as 'bla'

$ ppaste                   # Reads from the default clipboard and prints its contents
$ ppaste bar > bar.txt     # Reads 'bar' from the default clipboard to file 'bar.txt'
$ ppaste work:             # Reads from the 'work' clipboard and prints its contents
$ ppaste work:ho > ho.txt  # Reads 'ho' from the 'work' clipboard to file 'ho.txt'
```

More details can be found on the help page:
```bash 
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
