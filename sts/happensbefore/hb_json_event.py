from pox.lib.revent import Event

from collections import OrderedDict
import itertools
import json

class AttributeCombiningMetaclass(type):
  """
  Metaclass to allow union of arbitrary sequence attributes of base classes
  instead of overwriting them.
  Define attributes to combine by setting the attribute
  '_combiningmetaclass_args' in your class.
  
  Order is preserved: Elements from base classes are ordered first.
  """
  
  meta_args_name = '_attr_combining_metaclass_args'
  
  def __new__(cls, name, bases, attrs):
    if cls.meta_args_name in attrs:
      meta_args = attrs[cls.meta_args_name]
      combinable_attrs = meta_args
      del attrs[cls.meta_args_name]
      for attr_name in combinable_attrs:
#         a = []
#         if attr_name in attrs:
#           a = attrs[attr_name]
#         attr_type = type(a) # store type for later, hack
        all_attr_values = [list(attrs.get(attr_name, list()))]
        for base in bases:
          all_attr_values.insert(0,list(getattr(base, attr_name, list()))) # prepend
        
        attr_values = []
        for values in all_attr_values:
          for x in values:
            if x not in attr_values:
              attr_values.append(x)
#       attrs[attr_name] = type(attr_values) # hack, might not work
      attrs[attr_name] = list(attr_values)
    return type.__new__(cls, name, bases, attrs)


class JsonEvent(Event):
  
  _ids = itertools.count(0)
  _to_json_attrs = ['id',
                    'type']
  
  def __init__(self):
    Event.__init__(self)
    self.id = self._ids.next()
    self.type = self.__class__.__name__
  
  def to_json(self):
    json_dict = OrderedDict()
    for i in self._to_json_attrs:
      if isinstance(i, tuple):
        attr = i[0]
        fun = i[1]
        if hasattr(self, attr):
          json_dict[attr] = fun(getattr(self, attr))
      elif hasattr(self, i):
        json_dict[i] = getattr(self, i)
        
    return json.dumps(json_dict, sort_keys=False)