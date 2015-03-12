import itertools

class ObjectRegistry(object):
  """ Keeps track of a tag for Python objects
  """
  _it = itertools.count(1) # start at 1
  
  def __init__(self):
    self.tags = dict() # obj -> tag
    self.objs = dict() # tag -> obj
  
  def get_tag(self, obj):
    """ Get the tag for the object or assign a new unique tag for it.
    """
    if id(obj) in self.tags:
      return self.tags[id(obj)]
    else:
      tag = self._it.next()
      self.tags[id(obj)] = tag
      self.objs[tag] = obj
      return tag
    
  def get_obj(self, tag):
    if tag in self.objs:
      obj = self.objs[tag]
      return obj
    
  def new_tag(self, obj):
    """ Assign a new unique tag for the object.
    """
    if id(obj) in self.tags:
      del self.tags[id(obj)]
    return self.get_tag(obj)
  
  def remove_tag(self, obj):
    """ Remove an object (and tag)
    """
    if id(obj) in self.tags:
      tag = self.tags[id(obj)]
      del self.tags[id(obj)]
      del self.objs[tag]
      return True
    return False
  
  def remove_obj(self, tag):
    """ Remove a tag (and object)
    """
    if tag in self.objs:
      obj = self.objs[tag]
      return self.remove_tag(obj)
    return False
  
  def replace_obj(self, tag, obj):
    """ Replace the obj for a given tag, keeping the tag the same
    """
  
  def generate_unused_tag(self):
    return self._it.next()