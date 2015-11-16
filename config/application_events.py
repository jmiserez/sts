import sys
from threading import RLock
import itertools
import logging
import random
import json
import time
import pox.openflow.libopenflow_01 as of_01

import sts.replay_event
from sts.util.procutils import PopenTerminationEvent, popenTerminationPublisher, popen_background, cmdline_to_args,\
  popen_simple, popen_blocking

# TODO(jm): Figure out how to get logging working from here? logging.getLogger doesn't work.

class ControllerApp(object):
  
  # TODO(jm) document interface and who calls it
  def __init__(self, app_name):
    self.app_name = app_name
    
  def initialize(self):
    ''' Called in SimulationConfig.__init__ '''
    pass  
    
  def bootstrap(self):
    ''' Called in SimulationConfig.bootstrap'''
    pass
  
  def controller_connected(self):
    ''' Called in Fuzzer.loop(), Interactive.simulate'''
    pass
  
  def simulation_clean_up(self):
    ''' Called in Simulation.clean_up()'''
    pass
  
  def check_app_beginning(self, fuzzer):
    ''' Called in Fuzzer.loop()'''
    pass
  
  def check_app_before(self, fuzzer):
    ''' Called by Fuzzer.trigger_events before all other triggers'''
    pass
  
  def check_app_after(self, fuzzer):
    ''' Called by Fuzzer.trigger_events after all other triggers'''
    pass
  
  def proceed(self, event, simulation):
    ''' Called by Replayer through AppEvent.proceed when replaying an event'''
    pass
  
class AppFloodlightCircuitPusher(ControllerApp):
  def __init__(self, app_name, cwd, runtime, script, controller, background_process=False, wait_secs=0):
    super(AppFloodlightCircuitPusher, self).__init__(app_name)
    self._ids = itertools.count(0)
    self.cwd = cwd
    self.runtime = runtime
    self.script = script
    self.controller = controller
    
    self.pending_install = []
    self.installed = []
    self.pending_removal = []
    
    self.ip_pair_for_id = dict()
    self.free_ip_pairs = None
    self.circuited_ip_pairs = []
  
    self.ids = dict() # ids -> tuples
    
    self.background_process = background_process
    
    self.wait_secs = wait_secs
    self.last_action_time = None
    
    self.reentrantlock = RLock()    
    popenTerminationPublisher.addListener(PopenTerminationEvent, self._process_terminated)
    
    self.init_clean_up()
  
  def init_clean_up(self):
    args = cmdline_to_args('/bin/bash -c "rm -f circuits.json"')
    cmd = popen_simple(args, self.cwd)
  
  def _has_free_ip_pairs(self):
    return len(self.free_ip_pairs) > 0
  
  def _allocate_ip_pair(self, rng, circuit_id):
    chosen_pair = rng.choice(self.free_ip_pairs)
    self.free_ip_pairs.remove(chosen_pair)
    self.circuited_ip_pairs.append(chosen_pair)
    self.ip_pair_for_id[circuit_id] = chosen_pair
    return chosen_pair
    
  def _release_ip_pair(self, circuit_id):
    chosen_pair = self.ip_pair_for_id[circuit_id]
    self.circuited_ip_pairs.remove(chosen_pair)
    self.free_ip_pairs.append(chosen_pair)
    
  def _process_terminated(self, event):
    """
    The process was terminated, we get a PopenTerminationEvent
    """
    with self.reentrantlock:
#       print event.return_out
#       print event.return_err
      circuit_id = event.cmd_id
      if circuit_id in self.pending_install:
        if event.return_code == 0:
          self.pending_install.remove(circuit_id)
          self.installed.append(circuit_id)
          print "Installed circuit: " + str(circuit_id)
        else:
          # error
          print "Error installing circuit: {}. Stderr: {}, Stdout: {}".format(str(circuit_id), event.return_err, event.return_out)
          self.pending_install.remove(circuit_id)
      elif circuit_id in self.pending_removal:
        if event.return_code == 0:
          self.pending_removal.remove(circuit_id)
          del self.ids[circuit_id]
          self._release_ip_pair(circuit_id)
          print "Removed circuit: " + str(circuit_id)
        else:
          # error
          print "Error removing circuit: {}. Stderr: {}, Stdout: {}".format(str(circuit_id), event.return_err, event.return_out)
          self.pending_install.remove(circuit_id)
        
  def _install_circuits(self, fuzzer, num_circuits):
    with self.reentrantlock:
      num_remaining = num_circuits
      while self._has_free_ip_pairs() and num_remaining > 0:
        circuit_id = self._ids.next()
        c = self._allocate_ip_pair(fuzzer.random, circuit_id)
        print c
        self.ids[circuit_id] = c
        
        args = cmdline_to_args(self.runtime + ' ' + self.script + ' --controller ' + self.controller + 
                               ' --type ip --src ' + str(c[0].toStr()) + ' --dst ' + str(c[1].toStr()) + ' --add --name ' + str(circuit_id))

        if self.background_process:
          popen_background(circuit_id, args, self.cwd)
          print "Installing circuit in background: "+str(c[0].toStr()) + " <-> " + str(c[1].toStr() + " (id: " + str(circuit_id) + ")")
          # we will get notified when it is done
          self.pending_install.append(circuit_id)
        else:
          self.pending_install.append(circuit_id)
          print "Installing circuit (blocking): "+str(c[0].toStr()) + " <-> " + str(c[1].toStr() + " (id: " + str(circuit_id) + ")")
          event = popen_blocking(circuit_id, args, self.cwd)
          self._process_terminated(event)
        data = {'action' : 'add', 'args' : args, 'id' : circuit_id}
        fuzzer._log_input_event(sts.replay_event.AppEvent(self.app_name, data))
        num_remaining -= 1
          
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
        if self.background_process:
          cmd = popen_background(circuit_id, args, self.cwd)
          print "Removing circuit in background: " + str(circuit_id)
          # we will get notified when it is done
          self.pending_removal.append(circuit_id)
          self.installed.remove(circuit_id)
        else:
          self.pending_removal.append(circuit_id)
          self.installed.remove(circuit_id)
          print "Removing circuit (blocking): " + str(circuit_id)
          event = popen_blocking(circuit_id, args, self.cwd)
          self._process_terminated(event)
        data = {'action' : 'del', 'args' : args, 'id' : circuit_id}
        fuzzer._log_input_event(sts.replay_event.AppEvent(self.app_name, data))
        num_remaining -= 1

  def check_app_beginning(self, fuzzer):
    self.free_ip_pairs = []
    with self.reentrantlock:
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
                self.free_ip_pairs.append(candidate)
    print self.free_ip_pairs

  def check_app_before(self, fuzzer):
    pass
  
  def check_app_after(self, fuzzer):
    now = time.time()
    if self.last_action_time is None or (now - self.last_action_time) >= self.wait_secs:
      self.last_action_time = now
      if fuzzer.random.random() < fuzzer.params.app_floodlight_circuitpusher_add_rate:
        # try to add circuits
        self._install_circuits(fuzzer, fuzzer.params.app_floodlight_circuitpusher_add_parallelism)
      if fuzzer.random.random() < fuzzer.params.app_floodlight_circuitpusher_del_rate:
        # try to delete circuits
        self._remove_circuits(fuzzer, fuzzer.params.app_floodlight_circuitpusher_del_parallelism)
  
  def proceed(self, event, simulation):
    # TODO(jm): integrate with Replayer. At the moment far this function is never called.
    assert False
    return True


class AppFloodlightFirewall(ControllerApp):
  def __init__(self, app_name, cwd, controller):
    super(AppFloodlightFirewall, self).__init__(app_name)
    self._ids = itertools.count(0)
    self.cwd = cwd
    self.controller = controller
    
    self.pending_install = []
    self.installed = []
  
    self.ids = dict()
    self.ruleids = dict()
    
  def _enable_firewall(self):
    args = cmdline_to_args('curl -s -X GET'
                           ' http://%s/wm/firewall/module/enable/json'
                           % (self.controller
                              )
                           )
    max_rounds = 5
    round = 0
    while round < max_rounds:
      round += 1
#         print args
      event = popen_blocking(None, args, self.cwd)
      if event.return_code == 0:
        parsed_result = json.loads(event.return_out)
        print parsed_result
        assert "status" in parsed_result
        assert "details" in parsed_result
        assert parsed_result["status"] == "success"
        assert parsed_result["details"] == "firewall running"
        print "Firewall enabled."
        return
      else:
        # error
        print "Error enabling firewall. Stderr: {}, Stdout: {}".format(event.return_err, event.return_out)
        print "Waiting for 2s"
        time.sleep(2)
    assert False
    
  def _install_rules(self, fuzzer, allow_percentage):
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
    num_remaining = int(round(len(candidate_ip_pairs) * allow_percentage)) 
    while len(candidate_ip_pairs) > 0 and num_remaining > 0:
      c = fuzzer.random.choice(tuple(candidate_ip_pairs))
      candidate_ip_pairs.remove(c)
      rule_group_id = self._ids.next()
      self.ids[rule_group_id] = c
      self.ruleids[rule_group_id] = list()
      
      cmdlist = []
      
      cmdlist.append(cmdline_to_args('curl -s -X POST'
                                     ' http://%s/wm/firewall/rules/json'
                                     ' -d \''
                                     '{"src-ip": "%s/32",'
                                     ' "dst-ip": "%s/32",'
                                     ' "dl-type": "ARP"'
                                     '}\''
                                     % (self.controller,
                                        str(c[0].toStr()),
                                        str(c[1].toStr())
                                        )
                                     )
                     )
      cmdlist.append(cmdline_to_args('curl -s -X POST'
                                     ' http://%s/wm/firewall/rules/json'
                                     ' -d \''
                                     '{"src-ip": "%s/32",'
                                     ' "dst-ip": "%s/32",'
                                     ' "dl-type": "ARP"'
                                     '}\''
                                     % (self.controller,
                                        str(c[1].toStr()),
                                        str(c[0].toStr())
                                        )
                                     )
                     )
      cmdlist.append(cmdline_to_args('curl -s -X POST'
                                     ' http://%s/wm/firewall/rules/json'
                                     ' -d \''
                                     '{"src-ip": "%s/32",'
                                     ' "dst-ip": "%s/32",'
                                     ' "dl-type": "IPv4"'
                                     '}\''
                                     % (self.controller,
                                        str(c[1].toStr()),
                                        str(c[0].toStr())
                                        )
                                     )
                     )
      cmdlist.append(cmdline_to_args('curl -s -X POST'
                                     ' http://%s/wm/firewall/rules/json'
                                     ' -d \''
                                     '{"src-ip": "%s/32",'
                                     ' "dst-ip": "%s/32",'
                                     ' "dl-type": "IPv4"'
                                     '}\''
                                     % (self.controller,
                                        str(c[0].toStr()),
                                        str(c[1].toStr())
                                        )
                                     )
                     )
      cmdlist.append(cmdline_to_args('curl -s -X POST'
                                     ' http://%s/wm/firewall/rules/json'
                                     ' -d \''
                                     '{"src-ip": "%s/32",'
                                     ' "dst-ip": "%s/32",'
                                     ' "nw-proto": "ICMP"'
                                     '}\''
                                     % (self.controller,
                                        str(c[1].toStr()),
                                        str(c[0].toStr())
                                        )
                                     )
                     )
      cmdlist.append(cmdline_to_args('curl -s -X POST'
                                     ' http://%s/wm/firewall/rules/json'
                                     ' -d \''
                                     '{"src-ip": "%s/32",'
                                     ' "dst-ip": "%s/32",'
                                     ' "nw-proto": "ICMP"'
                                     '}\''
                                     % (self.controller,
                                        str(c[0].toStr()),
                                        str(c[1].toStr())
                                        )
                                     )
                     )
      print "Installing rule: "+str(c[0].toStr()) + " <-> " + str(c[1].toStr() + " (id: " + str(rule_group_id) + ")")
      for args in cmdlist:
#         print args
        event = popen_blocking(rule_group_id, args, self.cwd)
        if event.return_code == 0:
          parsed_result = json.loads(event.return_out)
          print parsed_result
          assert "status" in parsed_result
          assert "rule-id" in parsed_result
          assert parsed_result["status"] == "Rule added"
          ruleid = parsed_result["rule-id"]
          self.ruleids[rule_group_id].append(ruleid)
          print "Rule added: " + str(ruleid)
        else:
          # error
          print "Error installing rule: {}. Stderr: {}, Stdout: {}".format(str(rule_group_id), event.return_err, event.return_out)
          assert False
          
        data = {'action' : 'add', 'args' : args, 'id' : rule_group_id}
        
        fuzzer._log_input_event(sts.replay_event.AppEvent(self.app_name, data))
      num_remaining -= 1
    
  def check_app_beginning(self, fuzzer):
    self._enable_firewall()
    self._install_rules(fuzzer, fuzzer.params.app_floodlight_firewall_allow_percentage)

  def check_app_before(self, fuzzer):
    pass
  
  def check_app_after(self, fuzzer):
    pass
  
  def proceed(self, event, simulation):
    # TODO(jm): integrate with Replayer. At the moment far this function is never called.
    assert False
    return True
  
class AppFloodlightLoadBalancer(ControllerApp):
  def __init__(self, app_name, cwd, controller):
    super(AppFloodlightLoadBalancer, self).__init__(app_name)
    self._ids = itertools.count(1)
    self._hostids = itertools.count(1)
    self.cwd = cwd
    self.controller = controller
    
    self.pending_install = []
    self.installed = []
  
    self.poolids = dict()
    
    self.vips = list()
    
  def _add_vip(self, fuzzer, vip):
    self.vips.append(vip)
    fuzzer.params.vip_ip_list.append(vip)
    
  def _install_rules(self, fuzzer, pool_size):
    if pool_size > 0: # 0 disables load balancing
      remaining_hosts = set(fuzzer.simulation.topology.hosts)
      pools = list()
      current_pool = list()
      while len(remaining_hosts) > 0:
        if len(current_pool) < pool_size:
          # add a random host interface
          host = random.choice(tuple(remaining_hosts))
          remaining_hosts.remove(host)
          if len(host.interfaces) > 0:
            for i in host.interfaces:
              if i is not None and hasattr(i, 'ips') and len(i.ips) > 0:
                # add one of the ips
                current_pool.append(fuzzer.random.choice(i.ips))
        else:
          print current_pool
          pools.append(current_pool)
          current_pool = list()
      # last pool may be smaller
      pools.append(current_pool)
      
      while len(pools) > 0:
        c = pools.pop()
        
        pool_id = self._ids.next()
        self.poolids[pool_id] = c
        
        cmdlist = []
        
        vip = "10.0.0.%s" % str(100+pool_id)
        self._add_vip(fuzzer, vip)
        cmdlist.append(cmdline_to_args('curl -s -X POST'
                                       ' http://%s/quantum/v1.0/vips/'
                                       ' -d \''
                                       '{"id": "%s",'
                                       ' "name": "vip%s",'
                                       ' "protocol": "icmp",'
                                       ' "address": "%s",'
                                       ' "port":"8"'
                                       '}\''
                                       % (self.controller,
                                          pool_id,
                                          pool_id,
                                          str(vip)
                                          )
                                       )
                       )
        cmdlist.append(cmdline_to_args('curl -s -X POST'
                                       ' http://%s/quantum/v1.0/pools/'
                                       ' -d \''
                                       '{"id": "%s",'
                                       ' "name": "pool%s",'
                                       ' "protocol": "icmp",'
                                       ' "vip_id": "%s"'
                                       '}\''
                                       % (self.controller,
                                          pool_id,
                                          pool_id,
                                          pool_id
                                          )
                                       )
                       )
        for ip in c:
          host_id = self._hostids.next()
          cmdlist.append(cmdline_to_args('curl -s -X POST'
                                         ' http://%s/quantum/v1.0/members/'
                                         ' -d \''
                                         '{"id": "%s",'
                                         ' "address": "%s",'
                                         ' "port": "8",'
                                         ' "pool_id": "%s"'
                                         '}\''
                                         % (self.controller,
                                            host_id,
                                            ip,
                                            pool_id
                                            )
                                         )
                         )
        print "Installing pool: "+str(pool_id)
        for args in cmdlist:
          print args
          event = popen_blocking(pool_id, args, self.cwd)
          if event.return_code == 0:
            parsed_result = json.loads(event.return_out)
            print parsed_result
            assert "id" in parsed_result
          else:
            # error
            print "Error installing pool: {}. Stderr: {}, Stdout: {}".format(str(pool_id), event.return_err, event.return_out)
            assert False
            
        data = {'action' : 'add', 'args' : args, 'id' : pool_id}
        fuzzer._log_input_event(sts.replay_event.AppEvent(self.app_name, data))
    
  def check_app_beginning(self, fuzzer):
    self._install_rules(fuzzer, fuzzer.params.app_floodlight_load_balancer_pool_size)

  def check_app_before(self, fuzzer):
    pass
  
  def check_app_after(self, fuzzer):
    pass
  
  def proceed(self, event, simulation):
    # TODO(jm): integrate with Replayer. At the moment far this function is never called.
    assert False
    return True

