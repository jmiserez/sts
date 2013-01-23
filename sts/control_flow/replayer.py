'''
control flow for running the simulation forward.
  - Replayer: takes as input a `superlog` with causal dependencies, and
    iteratively prunes until the MCS has been found
'''

from sts.control_flow.interactive import Interactive
from sts.control_flow.event_scheduler import DumbEventScheduler, EventScheduler
from sts.replay_event import *
from sts.event_dag import EventDag
import sts.log_processing.superlog_parser as superlog_parser
from sts.util.console import color

from sts.control_flow.base import ControlFlow, ReplaySyncCallback

import signal
import sys
import time
import random
import logging

log = logging.getLogger("Replayer")

class Replayer(ControlFlow):
  # Runtime stats:
  total_replays = 0
  total_inputs_replayed = 0
  # Interpolated time parameter:
  time_epsilon_microseconds = 500

  '''
  Replay events from a `superlog` with causal dependencies, pruning as we go

  To set the event scheduling paramters, pass them as keyword args to the
  constructor of this class, which will pass them on to the EventScheduler object it creates.
  '''
  def __init__(self, simulation_cfg, superlog_path_or_dag, create_event_scheduler=None,
               print_buffers=True, wait_on_deterministic_values=False, auto_permit_dp_events=False, **kwargs):
    ControlFlow.__init__(self, simulation_cfg)
    if wait_on_deterministic_values:
      self.sync_callback = ReplaySyncCallback()
    else:
      self.sync_callback = ReplaySyncCallback(self.get_interpolated_time)

    if type(superlog_path_or_dag) == str:
      superlog_path = superlog_path_or_dag
      # The dag is codefied as a list, where each element has
      # a list of its dependents
      self.dag = EventDag(superlog_parser.parse_path(superlog_path))
    else:
      self.dag = superlog_path_or_dag

    self.print_buffers = print_buffers

    # compute interpolate to time to be just before first event
    self.compute_interpolated_time(self.dag.events[0])
    self.auto_permit_dp_events = auto_permit_dp_events

    if create_event_scheduler:
      self.create_event_scheduler = create_event_scheduler
    else:
      self.create_event_scheduler = \
        lambda simulation: EventScheduler(simulation,
            **{ k: v for k,v in kwargs.items()
                if k in EventScheduler.kwargs })

  def get_interpolated_time(self):
    '''
    During divergence, the controller may ask for the current time more or
    less times than they did in the original run. We control the time, so we
    need to give them some answer. The answers we give them should be
    (i) monotonically increasing, and (ii) between the time of the last
    recorded ("landmark") event and the next landmark event, and (iii)
    as close to the recorded times as possible

    Our temporary solution is to always return the time right before the next
    landmark
    '''
    # TODO(cs): implement Andi's improved time heuristic
    return self.interpolated_time

  def compute_interpolated_time(self, current_event):
    next_time = current_event.time
    just_before_micro = next_time.microSeconds - self.time_epsilon_microseconds
    just_before_micro = max(0, just_before_micro)
    self.interpolated_time = SyncTime(next_time.seconds, just_before_micro)

  def increment_round(self):
    msg.event(color.CYAN + ( "Round %d" % self.logical_time) + color.WHITE)
    pass

  def simulate(self, post_bootstrap_hook=None):
    ''' Caller *must* call simulation.clean_up() '''
    Replayer.total_replays += 1
    Replayer.total_inputs_replayed += len(self.dag.input_events)
    self.simulation = self.simulation_cfg.bootstrap(self.sync_callback)
    self.logical_time = 0
    self.run_simulation_forward(self.dag, post_bootstrap_hook)
    if self.print_buffers:
      self._print_buffers()
    return self.simulation

  def _print_buffers(self):
    log.debug("Pending Message Receives:")
    for p in self.simulation.god_scheduler.pending_receives():
      log.debug("- %s", p)
    log.debug("Pending State Changes:")
    for p in self.sync_callback.pending_state_changes():
      log.debug("- %s", p)

  def run_simulation_forward(self, dag, post_bootstrap_hook=None):
    event_scheduler = self.create_event_scheduler(self.simulation)
    if post_bootstrap_hook is not None:
      post_bootstrap_hook()

    exit_code = 0
    self.interrupted = False
    old_interrupt = None

    def interrupt(sgn, frame):
      msg.interactive("Interrupting fuzzer, dropping to console (press ^C again to terminate)")
      signal.signal(signal.SIGINT, self.old_interrupt)
      self.old_interrupt = None
      self.interrupted = True
      raise KeyboardInterrupt()
    self.old_interrupt = signal.signal(signal.SIGINT, interrupt)

    try:
      for event in dag.events:
        try:
          self.logical_time += 1
          self.compute_interpolated_time(event)
          event_scheduler.schedule(event)
          if self.auto_permit_dp_events:
            patch_panel = self.simulation.patch_panel
            for e in patch_panel.queued_dataplane_events:
              log.debug("Permitting dataplane event: %s" % str(e))
              patch_panel.permit_dp_event(e)
          self.increment_round()
        except KeyboardInterrupt as e:
          if self.interrupted:
            interactive = Interactive(self.simulation_cfg)
            interactive.simulate(self.simulation, bound_objects=( ('replayer', self), ))
            self.old_interrupt = signal.signal(signal.SIGINT, interrupt)
          else:
            raise e
    finally:
      if self.old_interrupt:
        signal.signal(signal.SIGINT, self.old_interrupt)
      msg.event(color.B_BLUE+"Event Stats: %s" % str(event_scheduler.stats))
