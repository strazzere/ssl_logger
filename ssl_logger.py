# Copyright 2017 Google Inc. All Rights Reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Decrypts and logs a process's SSL traffic.

Hooks the functions SSL_read() and SSL_write() in a given process and logs the
decrypted data to the console and/or to a pcap file.

  Typical usage example:

  ssl_log("wget", "log.pcap", True)

Dependencies:
  frida (https://www.frida.re/):
    sudo pip install frida
  hexdump (https://bitbucket.org/techtonik/hexdump/) if using verbose output:
    sudo pip install hexdump
"""

__author__ = "geffner@google.com (Jason Geffner)"
__version__ = "1.0"


import argparse
import os
import platform
import pprint
import random
import signal
import socket
import struct
import time

import frida

try:
  import hexdump  # pylint: disable=g-import-not-at-top
except ImportError:
  pass

# ssl_session[<SSL_SESSION id>] = (<bytes sent by client>,
#                                  <bytes sent by server>)
ssl_sessions = {}


def ssl_log(process, pcap=None, verbose=False, remote=False):
  """Decrypts and logs a process's SSL traffic.

  Hooks the functions SSL_read() and SSL_write() in a given process and logs
  the decrypted data to the console and/or to a pcap file.

  Args:
    process: The target process's name (as a string) or process ID (as an int).
    pcap: The file path to which the pcap file should be written.
    verbose: If True, log the decrypted traffic to the console.

  Raises:
    NotImplementedError: Not running on a Linux or macOS system.
  """

  if platform.system() not in ("Darwin", "Linux"):
    raise NotImplementedError("This function is only implemented for Linux and "
                              "macOS systems.")

  def log_pcap(pcap_file, ssl_session_id, function, src_addr, src_port,
               dst_addr, dst_port, data):
    """Writes the captured data to a pcap file.

    Args:
      pcap_file: The opened pcap file.
      ssl_session_id: The SSL session ID for the communication.
      function: The function that was intercepted ("SSL_read" or "SSL_write").
      src_addr: The source address of the logged packet.
      src_port: The source port of the logged packet.
      dst_addr: The destination address of the logged packet.
      dst_port: The destination port of the logged packet.
      data: The decrypted packet data.
    """
    t = time.time()

    if ssl_session_id not in ssl_sessions:
      ssl_sessions[ssl_session_id] = (random.randint(0, 0xFFFFFFFF),
                                      random.randint(0, 0xFFFFFFFF))
    client_sent, server_sent = ssl_sessions[ssl_session_id]

    if function == "SSL_read":
      seq, ack = (server_sent, client_sent)
    else:
      seq, ack = (client_sent, server_sent)

    for writes in (
        # PCAP record (packet) header
        ("=I", int(t)),                   # Timestamp seconds
        ("=I", int((t * 1000000) % 1000000)),  # Timestamp microseconds
        ("=I", int(40 + len(data))),           # Number of octets saved
        ("=i", int(40 + len(data))),           # Actual length of packet
        # IPv4 header
        (">B", 0x45),                     # Version and Header Length
        (">B", 0),                        # Type of Service
        (">H", 40 + len(data)),           # Total Length
        (">H", 0),                        # Identification
        (">H", 0x4000),                   # Flags and Fragment Offset
        (">B", 0xFF),                     # Time to Live
        (">B", 6),                        # Protocol
        (">H", 0),                        # Header Checksum
        (">I", src_addr),                 # Source Address
        (">I", dst_addr),                 # Destination Address
        # TCP header
        (">H", src_port),                 # Source Port
        (">H", dst_port),                 # Destination Port
        (">I", seq),                      # Sequence Number
        (">I", ack),                      # Acknowledgment Number
        (">H", 0x5018),                   # Header Length and Flags
        (">H", 0xFFFF),                   # Window Size
        (">H", 0),                        # Checksum
        (">H", 0)):                       # Urgent Pointer
      pcap_file.write(struct.pack(writes[0], writes[1]))
    pcap_file.write(data)

    if function == "SSL_read":
      server_sent += len(data)
    else:
      client_sent += len(data)
    ssl_sessions[ssl_session_id] = (client_sent, server_sent)

  def on_message(message, data):
    """Callback for errors and messages sent from Frida-injected JavaScript.

    Logs captured packet data received from JavaScript to the console and/or a
    pcap file. See https://www.frida.re/docs/messages/ for more detail on
    Frida's messages.

    Args:
      message: A dictionary containing the message "type" and other fields
          dependent on message type.
      data: The string of captured decrypted data.
    """
    if message["type"] == "error":
      pprint.pprint(message)
      os.kill(os.getpid(), signal.SIGTERM)
      return
    if len(data) == 0:
      return
    p = message["payload"]

    p["src_port"] = socket.ntohs(p["src_port"])
    p["dst_port"] = socket.ntohs(p["dst_port"])
    p["src_addr"] = socket.ntohl(p["src_addr"])
    p["dst_addr"] = socket.ntohl(p["dst_addr"])
    if verbose:
      src_addr = socket.inet_ntop(socket.AF_INET,
                                  struct.pack(">I", p["src_addr"]))
      dst_addr = socket.inet_ntop(socket.AF_INET,
                                  struct.pack(">I", p["dst_addr"]))
      print("SSL Session: " + p["ssl_session_id"])
      print("[%s] %s:%d --> %s:%d" % (
          p["function"],
          src_addr,
          p["src_port"],
          dst_addr,
          p["dst_port"]))
      hexdump.hexdump(data)
      print()
    if pcap:
      log_pcap(pcap_file, p["ssl_session_id"], p["function"], p["src_addr"],
               p["src_port"], p["dst_addr"], p["dst_port"], data)

  device = frida.get_usb_device()
  if remote:
    pid = device.spawn([process])
    session = device.attach(pid)
    # session=frida.get_remote_device().attach(process)
  else:
    session = frida.attach(process)

  if pcap:
    pcap_file = open(pcap, "wb", 0)
    for writes in (
        ("=I", 0xa1b2c3d4),     # Magic number
        ("=H", 2),              # Major version number
        ("=H", 4),              # Minor version number
        ("=i", time.timezone),  # GMT to local correction
        ("=I", 0),              # Accuracy of timestamps
        ("=I", 65535),          # Max length of captured packets
        ("=I", 228)):           # Data link type (LINKTYPE_IPV4)
      pcap_file.write(struct.pack(writes[0], writes[1]))

  scriptname = "ssl_logger_script.js"
  fd = open(scriptname, "r")
  script = session.create_script(fd.read())
  fd.close()
  script.on("message", on_message)
  script.load()
  if remote:
    device.resume(pid)

  print("Press Ctrl+C to stop logging.")
  try:
    signal.pause()
  except KeyboardInterrupt:
    pass

  session.detach()
  if pcap:
    pcap_file.close()


if __name__ == "__main__":

  class ArgParser(argparse.ArgumentParser):

    def error(self, message):
      print("ssl_logger v" + __version__)
      print("by " + __author__)
      print()
      print("Error: " + message)
      print()
      print(self.format_help().replace("usage:", "Usage:"))
      self.exit(0)

  parser = ArgParser(
      add_help=False,
      description="Decrypts and logs a process's SSL traffic.",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=r"""
Examples:
  %(prog)s -pcap ssl.pcap openssl
  %(prog)s -verbose 31337
  %(prog)s -pcap log.pcap -verbose wget
  %(prog)s -pcap log.pcap -verbose -remote com.google.chrome
""")

  args = parser.add_argument_group("Arguments")
  args.add_argument("-pcap", metavar="<path>", required=False,
                    help="Name of PCAP file to write")
  args.add_argument("-verbose", required=False, action="store_const",
                    const=True, help="Show verbose output")
  args.add_argument("-remote", required=False, action="store_const",
                    const=True, help="Attach a remote process")
  args.add_argument("process", metavar="<process name | process id>",
                    help="Process whose SSL calls to log")
  parsed = parser.parse_args()

  ssl_log(int(parsed.process) if parsed.process.isdigit() else parsed.process,
          parsed.pcap, parsed.verbose, parsed.remote)
