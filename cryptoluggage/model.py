#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Data model
"""

import datetime

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


class Dir(Node):
    """Directory (folder) node
    """

    def __init__(self, name, parent=None, children=None):
        super().__init__(name=name, parent=parent)
        self.children = [] if children is None else list(children)

    def __repr__(self):
        return f"Dir(name={repr(self.name)}, parent={repr(self.parent)}, children={repr(self.children)})"


class File(Node):
    """Encrypted file
    """

    def __init__(self, name, parent=None, token_id=None):
        super().__init__(name=name, parent=parent)
        self.token_id = token_id

    def __repr__(self):
        return f"File(name={repr(self.name)}, parent={repr(self.parent)}, token_id={self.token_id})"