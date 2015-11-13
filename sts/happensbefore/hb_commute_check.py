"""
Checks for commutativity rules
"""

from pox.openflow.libopenflow_01 import ofp_flow_mod
from pox.openflow.libopenflow_01 import ofp_match
from pox.openflow.libopenflow_01 import OFPFC_ADD
from pox.openflow.libopenflow_01 import OFPFC_DELETE
from pox.openflow.libopenflow_01 import OFPFC_DELETE_STRICT
from pox.openflow.libopenflow_01 import OFPFC_MODIFY
from pox.openflow.libopenflow_01 import OFPFC_MODIFY_STRICT
from pox.openflow.libopenflow_01 import OFPP_NONE
from pox.openflow.libopenflow_01 import OFPFF_CHECK_OVERLAP

from hb_utils import compare_flow_table
from hb_utils import read_flow_table
from hb_utils import write_flow_table


class CommutativityChecker(object):

  # TODO(jm): Move the code that does NOT use the commutativity specification to separate functions

  # TODO(jm): make use_comm_spec a config option
  def __init__(self, use_comm_spec=True):
    self.use_comm_spec = use_comm_spec # Use commutativity spec if True

  def is_flowmod_subset(self,e1,e2,strict=False):
    """
    Check if flow mod e1 is a subset of flow mod e2, with different semantics
    if the strict flag is True.
    """
    if strict:
      return e1.match == e2.match and e1.priority == e2.priority
    else:
      return e2.match.matches_with_wildcards(e1.match)

  def is_match_subset(self, m1, m2):
    """
    Check if match m1 is a subset of flow mod m2.
    """
    return m2.matches_with_wildcards(m1)

  def is_match_intersection_nonempty(self, m1, m2):
    """
    Check if there is a packet that can match both matches at the same time.

    This is implemented as described in "Header Space Analysis: Static
    Checking for Networks", http://dl.acm.org/citation.cfm?id=2228298.2228311

    "For two headers to have a non-empty intersection, both headers must have
    the same bit value at every position that is not a wildcard.

    Note: This is not currently supported by any version of POX, see the
          Github issue here for updates on the implementation:

          https://github.com/noxrepo/pox/issues/142

    """
    if isinstance(m1, ofp_flow_mod) and isinstance(m2, ofp_flow_mod):
      return m1.match.check_overlap(m2.match)
    if isinstance(m1, ofp_match) and isinstance(m2, ofp_match):
      return m1.check_overlap(m2)
    assert False

  def uses_outport(self, out_port, e):
    """
    Is out_port in any of the actions of e_actions?
    """
    if e.actions is not None:
      for a in e.actions:
        if hasattr(a, "type"):
          if a.type in (OFPAT_ENQUEUE, OFPAT_OUTPUT):
            if hasattr(a, "port"):
              if a.port == out_port:
                return True
    return False


  def deletes(self, edel, e, strict=False):
    """
    Does edel delete e?

    Note: If e is None then the answer is always False.

    DELETE and DELETE STRICT commands can be optionally filtered by out-
    put port. If the out_port field contains a value other than OFPP_NONE, it intro-
    duces a constraint when matching. This constraint is that the rule must contain
    an output action directed at that port. This field is ignored by ADD, MODIFY,
    and MODIFY STRICT messages.
    """
    if e is None:
      return False # TODO(jm): add documentation for this special case
    if e.out_port != OFPP_NONE:
      has_outport = self.uses_outport(e.out_port, edel)
      return self.is_flowmod_subset(e, edel, strict) and has_outport
    else:
      return self.is_flowmod_subset(e, edel, strict)

  def is_add(self, fm):
    return fm.command == OFPFC_ADD
  def is_del(self, fm):
    return fm.command in (OFPFC_DELETE, OFPFC_DELETE_STRICT)
  def is_mod(self, fm):
    return fm.command in (OFPFC_MODIFY, OFPFC_MODIFY_STRICT)
  def is_strict(self, fm):
    return fm.command in (OFPFC_DELETE_STRICT, OFPFC_MODIFY_STRICT)
  def is_check_overlap_flag(self, fm):
    if (fm.flags & OFPFF_CHECK_OVERLAP):
      return True
    return False

  def nocommute_read_add(self, pkt, eread, eadd, read_id, add_id):
    if add_id < read_id:
      if eread is None:
        return False
      else:
        # only compare select fields, we don't want to compare statistics
        return (
        eread.priority == eadd.priority and
        eread.match == eadd.match and
        eread.actions == eadd.actions
        )
    else:
      if eread is None:
        return self.is_match_subset(pkt, eadd.match)
      else:
        return self.is_match_subset(pkt, eadd.match) and eread.priority <= eadd.priority and eread.actions != eadd.actions

  def nocommute_read_mod(self, pkt, eread, emod, read_id, mod_id):
    if mod_id < read_id:
      if eread is None:
        return False
      else:
        return self.is_flowmod_subset(eread, emod, self.is_strict(emod)) and eread.actions == emod.actions
    else:
      if eread is None:
        return False
      else:
        return self.is_match_subset(pkt, emod.match) and eread.actions != emod.actions

  def nocommute_read_del(self, pkt, eread, edel, read_id, del_id):
    if del_id < read_id:
      return self.is_match_subset(pkt, edel.match)
    else:
      return self.deletes(edel,eread,self.is_strict(edel)) # False if eread is None

  def nocommute_del_mod(self, edel, emod):
    if self.is_strict(emod):
      return self.deletes(edel, emod, True)
    else:
      return self.is_match_intersection_nonempty(edel.match, emod.match)

  def nocommute_add_del(self, eadd, edel):
    return (
            self.deletes(edel, eadd, self.is_strict(edel)) or
            (self.is_check_overlap_flag(eadd) and self.is_match_intersection_nonempty(eadd, edel))
            )

  def nocommute_mod_mod(self, e1, e2):
    strict1 = self.is_strict(e1)
    strict2 = self.is_strict(e2)
    if not strict1 and not strict2:
      return (self.is_match_intersection_nonempty(e1, e2) and
              e1.actions != e2.actions
              )
    if strict1 and strict2:
      return (e1.match == e2.match and
              e1.priority == e2.priority and
              e1.actions != e2.actions
              )
    return ((self.is_flowmod_subset(e1, e2, strict2) or self.is_flowmod_subset(e2, e1, strict1)) and
            e1.actions != e2.actions
            )

  def nocommute_add_mod(self, eadd, emod):
    if not self.is_check_overlap_flag(eadd):
      return self.is_flowmod_subset(eadd, emod, self.is_strict(emod)) and eadd.actions != emod.actions
    else:
      return self.is_match_intersection_nonempty(eadd, emod)

  def nocommute_add_add(self, e1, e2, no_overlap1=False, no_overlap2=False):
    if no_overlap1 or no_overlap2:
      return self.is_match_intersection_empty(e1,e2) and e1.priority == e2.priority
    else:
      return e1.match == e2.match and e1.priority == e2.priority and e1.actions != e2.actions

  def check_comm_spec_ww(self, i_event, i_op, k_event, k_op):
    i_fm = i_op.flow_mod
    i_fm.match.wildcards = i_fm.match._unwire_wildcards(i_fm.match.wildcards)
    i_fm.match.wildcards = i_fm.match._normalize_wildcards(i_fm.match.wildcards)

    k_fm = k_op.flow_mod
    k_fm.match.wildcards = k_fm.match._unwire_wildcards(k_fm.match.wildcards)
    k_fm.match.wildcards = k_fm.match._normalize_wildcards(k_fm.match.wildcards)

    # del mod
    if self.is_del(i_fm) and self.is_mod(k_fm):
      return not self.nocommute_del_mod(i_fm, k_fm)
    if self.is_mod(i_fm) and self.is_del(k_fm):
      return not self.nocommute_del_mod(k_fm, i_fm)

    # add del
    if self.is_add(i_fm) and self.is_del(k_fm):
      return not self.nocommute_add_del(i_fm, k_fm)
    if self.is_del(i_fm) and self.is_add(k_fm):
      return not self.nocommute_add_del(k_fm, i_fm)

    # mod mod
    if self.is_mod(i_fm) and self.is_mod(k_fm):
      return not self.nocommute_mod_mod(i_fm, k_fm)

    # add mod
    if self.is_add(i_fm) and self.is_mod(k_fm):
      return not self.nocommute_add_mod(i_fm, k_fm)
    if self.is_mod(i_fm) and self.is_add(k_fm):
      return not self.nocommute_add_mod(k_fm, i_fm)

    # add add
    if self.is_add(i_fm) and self.is_add(k_fm):
      return not self.nocommute_add_add(i_fm, k_fm)

    # del del
    if self.is_del(i_fm) and self.is_del(k_fm):
      return True # always commutes!

    print "Warning: Unhandled w/w commutativity case!"
    assert False

  def check_comm_spec_rw(self, i_event, i_op, k_event, k_op):

    pkt_match = ofp_match.from_packet(i_event.packet, i_event.in_port)

    pkt_match.wildcards = pkt_match._unwire_wildcards(pkt_match.wildcards)
    pkt_match.wildcards = pkt_match._normalize_wildcards(pkt_match.wildcards)

    # may be None
    i_retval = i_op.flow_mod
    if i_retval is not None:
      i_retval.match.wildcards = i_retval.match._unwire_wildcards(i_retval.match.wildcards)
      i_retval.match.wildcards = i_retval.match._normalize_wildcards(i_retval.match.wildcards)

    k_fm = k_op.flow_mod
    k_fm.match.wildcards = k_fm.match._unwire_wildcards(k_fm.match.wildcards)
    k_fm.match.wildcards = k_fm.match._normalize_wildcards(k_fm.match.wildcards)

    # add
    if self.is_add(k_fm):
      return not self.nocommute_read_add(pkt_match, i_retval, k_fm, i_event.eid, k_event.eid)

    # del
    if self.is_del(k_fm):
      return not self.nocommute_read_del(pkt_match, i_retval, k_fm, i_event.eid, k_event.eid)

    # mod
    if self.is_mod(k_fm):
      return not self.nocommute_read_mod(pkt_match, i_retval, k_fm, i_event.eid, k_event.eid)

    print "Warning: Unhandled r/w commutativity case!"
    assert False

  def check_commutativity_ww(self, i_event, i_op, k_event, k_op):
    if self.use_comm_spec:
      return self.check_comm_spec_ww(i_event, i_op, k_event, k_op)

    # TODO(jm): Add flag so that we can also check the simulation, and verify
    #           or compare the spec with the simulated/simple version.
    #           Note that in some cases the spec may be more accurate!

    ik_table = i_op.flow_table
    write_flow_table(ik_table, i_op.flow_mod)
    write_flow_table(ik_table, k_op.flow_mod)

    ki_table = k_op.flow_table
    write_flow_table(ki_table, k_op.flow_mod)
    write_flow_table(ki_table, i_op.flow_mod)

    if compare_flow_table(ik_table, ki_table):
      return True
    else:
      return False

  def check_commutativity_rw(self, i_event, i_op, k_event, k_op):
    if self.use_comm_spec:
      return self.check_comm_spec_rw(i_event, i_op, k_event, k_op)

    if i_event.eid < k_event.eid: # read occurred first in trace
      ik_table = i_op.flow_table
      ki_table = i_op.flow_table
    else: # write occurred first in trace
      ik_table = k_op.flow_table
      ki_table = k_op.flow_table

    ik_retval = read_flow_table(ik_table, i_event.packet, i_event.in_port)
    write_flow_table(ik_table, k_op.flow_mod)

    write_flow_table(ki_table, k_op.flow_mod)
    ki_retval = read_flow_table(ki_table, i_event.packet, i_event.in_port)

    ik_fm = None if ik_retval is None else ik_retval.to_flow_mod()
    ki_fm = None if ki_retval is None else ki_retval.to_flow_mod()

    if (ik_fm == ki_fm and compare_flow_table(ik_table, ki_table)):
      return True
    else:
      return False
