# Packet filter tester with mininet

## install

- install lagopus
- install ryu

And install mininet with lagopus.

```
$ git clone https://github.com/lagopus/mininet
$ cd mininet
$ git checkout lagopus
$ ./util/install.sh -fnv
```

## Usage

- Tester

```
$ cd lagofirewall/test
$ ./tester.sh
```

- Mininet

```
$ cd lagofirewall/test/mininet
$ sudo ./fw_test.py
```

- Firewall

```
$ cd lagopusfirewall
$ ryu-manager lagofirewall.py /path/to/ryu/app/ofctl_rest.py
```

```
$ cd lagopusfirewall
$ add [your rule]

...

$ 
```

