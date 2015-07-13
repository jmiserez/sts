import sys
from threading import RLock
import itertools
import pox.openflow.libopenflow_01 as of_01

import sts.replay_event
from sts.util.procutils import PopenTermination, popenTerminationPublisher, popen_background, cmdline_to_args,\
  popen_simple, popen_blocking

class ControllerApp(object):
  
  # TODO(jm) document interface and who calls it
  def __init__(self, app_name):
    self.app_name = app_name
  
  def check_app_before(self, fuzzer):
    pass
  
  def check_app_after(self, fuzzer):
    pass
  
  def proceed(self, event, simulation):
    pass
  
class AppCircuitPusher(ControllerApp):
  def __init__(self, app_name, cwd, runtime, script, controller):
    super(AppCircuitPusher, self).__init__(app_name)
    self._ids = itertools.count(0)
    self.cwd = cwd
    self.runtime = runtime
    self.script = script
    self.controller = controller
    
    self.pending_install = []
    self.installed = []
    self.pending_removal = []
  
    self.ids = dict() # ids -> tuples
    
    self.reentrantlock = RLock()    
    popenTerminationPublisher.addListener(PopenTermination, self._process_terminated)
    
    self.clean_up()
    
  def clean_up(self):
    args = cmdline_to_args('/bin/bash -c "rm -f circuits.json"')
    cmd = popen_simple(args, self.cwd)
    
  def _process_terminated(self, event):
    with self.reentrantlock:
      circuit_id = event.cmd_id
      if circuit_id in self.pending_install:
        self.pending_install.remove(circuit_id)
        self.installed.append(circuit_id)
      elif circuit_id in self.pending_removal:
        self.pending_removal.remove(circuit_id)
        del self.ids[circuit_id]
        
  def _install_circuits(self, fuzzer, num_circuits):
    with self.reentrantlock:
      candidate_ip_pairs = set()
      host_pairs = itertools.combinations(fuzzer.simulation.topology.hosts, 2)
      for p in host_pairs:
        h1 = p[0]
        h2 = p[1]
        if len(h1.interfaces) > 0 and len(h2.interfaces) > 0:
          interface_pairs = itertools.product(h1.interfaces, h2.interfaces)
          for i in interface_pairs:
            i1 = i[0]
            i2 = i[1]
            if i1 is not None and hasattr(i1, 'ips') and i2 is not None and hasattr(i2, 'ips') and len(i1.ips) > 0 and len(i2.ips) > 0:
              ip_pairs = itertools.product(i1.ips, i2.ips)
              for candidate in ip_pairs:
                inverse = (candidate[1], candidate[0])
                if (candidate not in self.ids.items() and
                    inverse not in self.ids.items()):
                  candidate_ip_pairs.add(candidate)
      num_remaining = num_circuits
      while len(candidate_ip_pairs) > 0 and num_remaining > 0:
        c = fuzzer.random.choice(tuple(candidate_ip_pairs))
        candidate_ip_pairs.remove(c)
        circuit_id = self._ids.next()
        self.ids[circuit_id] = c
        
        args = cmdline_to_args(self.runtime + ' ' + self.script + ' --controller ' + self.controller + 
                               ' --type ip --src ' + str(c[0].toStr()) + ' --dst ' + str(c[1].toStr()) + ' --add --name ' + str(circuit_id))
#     args = cmdline_to_args('bash -c "ls -al; pwd"')
        cmd = popen_background(circuit_id, args, self.cwd)
#         event = popen_blocking(circuit_id, args, self.cwd)
        # we will get notified when it is done
        self.pending_install.append(circuit_id)
        data = {'action' : 'add', 'args' : args, 'id' : circuit_id}
        fuzzer._log_input_event(sts.replay_event.AppEvent(self.app_name, data))
        num_remaining -= 1
#         self._process_terminated(event)
    
  def _remove_circuits(self, fuzzer, num_circuits):
    with self.reentrantlock:
      num_remaining = num_circuits
      while len(self.installed) > 0 and num_remaining > 0:
        circuit_id = fuzzer.random.choice(self.installed)
        assert circuit_id not in self.pending_install
        assert circuit_id not in self.pending_removal
        assert circuit_id in self.installed
        args = cmdline_to_args(self.runtime + ' ' + self.script + ' --controller ' + self.controller + 
                               ' --delete --name ' + str(circuit_id))
        cmd = popen_background(circuit_id, args, self.cwd)
        # we will get notified when it is done
        self.pending_removal.append(circuit_id)
        self.installed.remove(circuit_id)
        data = {'action' : 'del', 'args' : args, 'id' : circuit_id}
        fuzzer._log_input_event(sts.replay_event.AppEvent(self.app_name, data))
        num_remaining -= 1

  def check_app_before(self, fuzzer):
    pass
  
  def check_app_after(self, fuzzer):
    if fuzzer.random.random() < fuzzer.params.app_circuitpusher_add_rate:
      # try to add circuits
      self._install_circuits(fuzzer, fuzzer.params.app_circuitpusher_add_parallelism)
    if fuzzer.random.random() < fuzzer.params.app_circuitpusher_del_rate:
      # try to delete circuits
      self._remove_circuits(fuzzer, fuzzer.params.app_circuitpusher_del_parallelism)
  
  def proceed(self, event, simulation):
    # TODO(jm): integrate with Replayer. At the moment far this function is never called.
    assert False
    return True

