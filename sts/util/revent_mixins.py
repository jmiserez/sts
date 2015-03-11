'''
Created on Feb 5, 2015

@author: jeremie
'''

import abc

class CombiningEventMixinMetaclass(type):
  """
  Metaclass to allow union of _eventMixin_events attributes of base classes
  instead of overwriting them.
  """
  def __new__(cls, name, bases, attrs):
    _eventMixin_events = set(attrs.get('_eventMixin_events', list()))
    for base in bases:
      _eventMixin_events.update(getattr(base,'_eventMixin_events', list()))
    attrs['_eventMixin_events'] = _eventMixin_events
    return type.__new__(cls, name, bases, attrs)
  
class AbstractCombiningEventMixinMetaclass(abc.ABCMeta):
  def __new__(cls, name, bases, attrs):
    _eventMixin_events = set(attrs.get('_eventMixin_events', list()))
    for base in bases:
      _eventMixin_events.update(getattr(base,'_eventMixin_events', list()))
    attrs['_eventMixin_events'] = _eventMixin_events
    return abc.ABCMeta.__new__(cls, name, bases, attrs) 
