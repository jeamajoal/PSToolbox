#!/usr/bin/env python
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Author::     Eric DePree
# Copyright::  Copyright (c) 2014
# License::    GPLv2
#Updated by jeamajoal.    Made secure upload work.

#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

import os
import ssl
import time
import signal
import logging
import argparse

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import BaseHTTPServer, SimpleHTTPServer

# Global Variables :-(
args = None

class ServerHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler that supports POST commands"""

    def do_POST(self):
        start_time = time.time()

        logging.info("Received an HTTP POST")
        logging.info("Headers are [{}]".format(self.headers))

        # Process header information
        content_boundry = self.headers['Content-Type'].split('=')[1]
        length_in_bytes = int(self.headers['Content-Length'])

        logging.debug("Boundary [{}] Content-Length [{}]".format(content_boundry, length_in_bytes))

        # Enter the download boundary
        line = self.rfile.readline()
        length_in_bytes -= len(line)

        if not content_boundry in line:
            logging.error("The download content does not have the appropriate boundary [{}]".format(content_boundry))
            self.send_response(500)
            return

        # Get the filename
        line = self.rfile.readline()
        length_in_bytes -= len(line)
        # Remove leading quote and training quote plus CRLF
        filename = line.split('=')[2][1:-3]

        if not filename:
            logging.error("Cannot find the filename in the HTTP request")
            self.send_response(500)
            return

        logging.info("Received a request to save the file [{}]".format(filename))

        # Burn two lines
        length_in_bytes -= len(self.rfile.readline())
        length_in_bytes -= len(self.rfile.readline())

        # Write the file to disk
        abosulte_path_output_file = os.path.join(args.output_folder, filename)

        logging.debug("Starting the download to [{}]".format(abosulte_path_output_file))

        with open(abosulte_path_output_file, 'wb') as output_file:
            while length_in_bytes > 0:
                line = self.rfile.readline()
                length_in_bytes -= len(line)

                # Check for ending boundary
                if content_boundry in line:
                    elapsed_time = time.time() - start_time
                    logging.info("Upload completed in [{}] seconds".format(elapsed_time))
                else:
                    output_file.write(line)


def run_http_server():
    """Run an HTTP server till it's terminated"""

    logging.debug("Building server to listen to [{}] on port [{}]".format(args.address, args.port))

    # Configure HTTP server
    server = HTTPServer((args.address, args.port), ServerHandler)
    server.serve_forever()

    logging.info("Server running")

def run_https_server():
    """Run an HTTPS server till it's terminated. This is still experimental"""

    logging.debug("Building HTTPS server to listen to [{}] on port [{}]".format(args.address, args.port))

    # Configure HTTPS server
    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path)
    certcrtpath = script_dir + '/server.pem'
    server = HTTPServer((args.address, args.port), ServerHandler)
    server.socket = ssl.wrap_socket(server.socket, server_side=True, certfile=certcrtpath)
    server.serve_forever()

    logging.info("Server is running")


if __name__ == '__main__':
    # Command line arguments
    parser = argparse.ArgumentParser(description="Simple HTTP(S) server that accepts POST requests.")

    parser.add_argument("-a", dest="address", default="localhost", help="Address [Default: localhost]")
    parser.add_argument("-p", dest="port", type=int, default=5000, help="Port Number [Default: 5000]")
    parser.add_argument("-o", dest="output_folder", default="/tmp", help="Output Folder for Downloads [Default: /tmp]")
    parser.add_argument("-v", dest="verbosity", action="store_true", help="Increase Verboseness of Logging.")
    parser.add_argument("-s", dest="secure", action="store_true", help="Use TLS. mydomain.crt and mydomain.key must exist.")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(format="%(asctime)-19s %(levelname)-8s %(message)s",
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=10 if args.verbosity else 20)

    # Capture SIGINT
    signal.signal(signal.SIGINT, lambda x, y: exit(-1))

    # Run
    logging.info("Starting the server")
    if args.secure:
        run_https_server()
    else:
        run_http_server()

