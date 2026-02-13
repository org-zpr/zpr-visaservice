# zpt -- ZPR Policy Tester

Command-line tool for testing how `libeval` evaluates ZPR policies. Supports
both an interactive REPL and a batch/script mode.


## Usage

```
zpt                        # start interactive REPL
zpt -i instructions.txt    # run instructions from a file
zpt -i -                   # read instructions from stdin
zpt -j -i instructions.txt # output in JSONL format
zpt -v                     # enable debug logging from libeval
```


## Commands

### load

Load a compiled policy file.

```
load path/to/policy.bin
```

### set

Set attributes on a named actor. Actors are created on first use.

```
set alice user.color:red
set alice zpr.services:web
set alice roles:{marketing, management}
```

### eval

Evaluate a packet against the loaded policy.

**TCP:**
```
eval tcp alice.12345 > bob.80 [S]
```

Flag notation: `[S]` SYN, `[S.]` SYN+ACK, `[P.]` PUSH+ACK, `[R]` RST,
`[F.]` FIN+ACK.

**UDP:**
```
eval udp alice.5000 > bob.5000
```

**ICMPv6:**
```
eval icmp6 alice > bob echo-request
eval icmp6 alice > bob 128:0
```

Ports are optional for the source actor; a random high port is used when
omitted.

### connect

Test connection approval with authenticated and/or unauthenticated claims.

```
connect --ac cn:mynode.example.com --ac role:node --uc zpr.addr:fd00::1
```

### dumpdb

Print the current actor database.

```
dumpdb
```


## Example Session

```
$ zpt
zpt> load policy.bin
zpt> set client zpr.addr:fd00::1
zpt> set server zpr.addr:fd00::2
zpt> set server zpr.services:web
zpt> eval tcp client > server.443 [S]
```


## Building

```bash
make all
```
