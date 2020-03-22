#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Data model
"""

import os
import datetime
import sortedcontainers

############################ Begin configurable part

# Be verbose?
be_verbose = True


############################ End configurable part

class Secret:
    """Secret stored in the Luggage
    """

    def __init__(self, name="", contents="", tags=[], last_updated=None):
        """
        :param name: string containing the name of the secret, like "dropbox.com"
        :param contents: string with the secret contents, like "user: user\npass: pass"
        :param tags: list of strings with the tags associated to this secret
        :param last_updated: datetime.datetime of the last update of this secret (use None for now)
        """
        name = name.strip()
        contents = contents.strip()
        tags = list(map(str.strip, list(map(str, tags))))
        if last_updated == None:
            last_updated = datetime.datetime.now()
        assert (type(tags) is list)

        self.name = str(name)
        self.contents = str(contents)
        self.tags = [s.strip().lower() for s in tags]
        self.last_updated = last_updated

    def __repr__(self):
        return f"Secret(name={repr(self.name)}, contents={repr(self.contents)}, " \
               f"tags={self.tags}, last_updated={self.last_updated})"


class Node:
    """Node in the encrypted file system
    """

    def __init__(self, name, parent):
        self.name = name
        self.parent = parent

    @property
    def path(self):
        elements = [self.name]
        s = self
        while s.parent is not None:
            elements.append(s.parent.name if s.parent.parent is not None else '')
            s = s.parent
        return os.sep.join(reversed(elements))


class Dir(Node):
    """Directory (folder) node
    """
    def __init__(self, name, parent=None, children=None):
        super().__init__(name=name, parent=parent)
        self.children = sortedcontainers.SortedDict() if children is None \
            else sortedcontainers.SortedDict({c.name: c for c in children})
        print(f">>>>> Creating dir name={name} self.children={self.children}")

    def get_descendent_files(self):
        """Generator of all model.File instances contained in this directory,
        or any of its descendent subdirs.
        """
        pending_nodes = [self]
        seen_nodes = set()
        while pending_nodes:
            node = pending_nodes.pop()
            try:
                for child in node.children.values():
                    if child in seen_nodes:
                        raise RuntimeError("Circular refernce")
                    pending_nodes.append(child)
                    seen_nodes.add(child)
            except AttributeError:
                yield node

    def __iter__(self):
        """Iterate over children of this dir
        """
        return iter(self.children.values())

    def __repr__(self):
        return f"Dir(name={repr(self.name)}, " \
               f"parent={repr(self.parent.name) if self.parent is not None else None}, " \
               f"children={repr(','.join(c.name for c in self.children.values()))})"


class File(Node):
    """Encrypted file
    """

    def __init__(self, name, parent=None, token_id=None):
        super().__init__(name=name, parent=parent)
        self.token_id = token_id

    def __repr__(self):
        return f"File(name={repr(self.name)}, parent={repr(self.parent.name)}, token_id={self.token_id})"
