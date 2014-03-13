# Copyright 2014 Ahmed El-Hassany
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Define base (mostly abstract) entities used by sts.
"""


import abc
import logging


class DirectedLinkAbstractClass(object):
  """
  A directed network link
  """
  __metaclass__ = abc.ABCMeta

  def __init__(self, start_node, start_port, end_node, end_port):
    """
    Init new directed link.

    start_port has to be member of start_node, likewise for end_port
    """
    if hasattr(start_node, 'has_port'):
      assert start_node.has_port(start_node)
    if hasattr(end_node, 'has_port'):
      assert end_node.has_port(end_node)
    self._start_node = start_node
    self._start_port = start_port
    self._end_node = end_node
    self._end_port = end_port

  @property
  def start_node(self):
    """The starting node"""
    return self._start_node

  @property
  def start_port(self):
    """The starting port"""
    return self._start_port

  @property
  def end_node(self):
    """The destination node"""
    return self._end_node

  @property
  def end_port(self):
    """The destination port"""
    return self._end_port

  def __eq__(self, other):
    return (self.start_node == getattr(other, 'start_node', None) and
            self.start_port == getattr(other, 'start_port', None) and
            self.end_node == getattr(other, 'end_node', None) and
            self.end_port == getattr(other, 'end_port', None))

  def __ne__(self, other):
    return not self.__eq__(other)

  def __repr__(self):
    return "(%d:%d) -> (%d:%d)" % (self.start_node, self.start_port,
                                   self.end_node, self.end_port)

  def create_reversed_link(self):
    """Create a Link that is in the opposite direction of this Link."""
    return DirectedLinkAbstractClass(self.end_node, self.end_port,
                                     self.start_node, self.start_port)


class BiDirectionalLinkAbstractClass(object):
  """
  An bi-directed network link
  """
  __metaclass__ = abc.ABCMeta

  def __init__(self, node1, port1, node2, port2):
    if hasattr(node1, 'has_port'):
      assert node1.has_port(port1)
    if hasattr(node2, 'has_port'):
      assert node2.has_port(port2)
    self._node1 = node1
    self._port1 = port1
    self._node2 = node2
    self._port2 = port2

  @property
  def node1(self):
    return self._node1

  @property
  def port1(self):
    return self._port1

  @property
  def node2(self):
    return self._node2

  @property
  def port2(self):
    return self._port2

  def __eq__(self, other):
    return ((self.node1 == getattr(other, 'node1', None) and
             self.port1 == getattr(other, 'port1', None) and
             self.node2 == getattr(other, 'node2', None) and
             self.port2 == getattr(other, 'port2', None)) or
             (self.node1 == getattr(other, 'node2', None) and
              self.port1 == getattr(other, 'port2', None) and
              self.node2 == getattr(other, 'node1', None) and
              self.port2 == getattr(other, 'port1', None)))

  def __ne__(self, other):
    return not self.__eq__(other)

  def __repr__(self):
    return "(%d:%d) <-> (%d:%d)" % (self.node1, self.port1,
                                    self.node2, self.port2)


class SSHEntity(object):
  """
  Controls an entity via ssh.

  If username, password, and key_filename are None, the SSH will be use the
  default ssh key loaded into the system and will work if the destination
  host is configured to accept that key.

  Args:
    host: the server address to connect to.
    port: the server port to connect to (default 22)
    username: the username to authenticate as (default local username)
    password: password to authenticate or to unlock the private key
    key_filename: private key for authentication
  """
  def __init__(self, host, port=22, username=None, password=None,
               key_filename=None, ssh_cls=None):
    self._host = host
    self._port = port
    self._username = username
    self._password = password
    self._key_filename = key_filename
    self._ssh_client = None
    self._ssh_cls = ssh_cls
    if self._ssh_cls is None:
      try:
        import paramiko
      except ImportError:
        raise RuntimeError('''Must install paramiko to use ssh: \n'''
                           ''' $ sudo pip install paramiko ''')
      # Suppress normal SSH messages
      logging.getLogger("paramiko").setLevel(logging.WARN)
      self._ssh_cls = paramiko.SSHClient
    self.log = logging.getLogger("SSHEntity")

  @property
  def host(self):
    """The server address to connect to"""
    return self._host

  @property
  def port(self):
    """The server port to connect to"""
    return self._port

  @property
  def username(self):
    """The username to authenticate as (default local username)"""
    return self._username

  @property
  def password(self):
    """Password to authenticate or to unlock the private key."""
    return self._password

  @property
  def key_filename(self):
    """Private key for authentication"""
    return self._key_filename

  @property
  def ssh_cls(self):
    """
    Returns reference to the SSH Client class
    """
    return self._ssh_cls

  @property
  def check_key_policy(self):
    """
    Returns the the policy for missing host keys

    Default: accept all keys
    """
    try:
      import paramiko
    except ImportError:
      raise RuntimeError('''Must install paramiko to use ssh: \n'''
                         ''' $ sudo pip install paramiko ''')
    return paramiko.AutoAddPolicy()

  @property
  def ssh_client(self):
    """Returns instance of the ssh client

    Will connect to the host if not already connected.
    """
    if self._ssh_client is None:
      self._ssh_client = self.ssh_cls()
      # Ignore host identify check
      self._ssh_client.set_missing_host_key_policy(self.check_key_policy)
      self._ssh_client.connect(hostname=self.host, port=self.port,
                               username=self.username, password=self.password,
                               key_filename=self.key_filename)
    return self._ssh_client

  def get_new_session(self):
    """Return new ssh session handler to the host"""
    ssh = self.ssh_client
    transport = ssh.get_transport()
    session = transport.open_channel(kind='session')
    return session

  def execute_remote_command(self, cmd, max_iterations=10):
    """
    Execute command remotely and return the stdout results
    """
    while max_iterations > 0:
      try:
        session = self.get_new_session()
        session.exec_command(cmd)
        reply = ""
        while True:
          if session.recv_ready():
            reply += session.recv(100)  # arbitrary
          elif session.recv_ready() is False and session.exit_status_ready():
            break
        session.close()
        return reply
      except Exception as exp:
        self.log.warn("Exception in executing remote command \"%s\": %s" %
                      (cmd, self.host))
        print self.log.error(exp)
        self._ssh_client = None
        max_iterations -= 1
    return ""

  def __del__(self):
    if self._ssh_client:
      try:
        self._ssh_client.close()
      except Exception as exp:
        self.log.warn("Error at closing ssh connection: '%s'" % exp)
