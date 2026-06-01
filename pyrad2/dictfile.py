"""Dictionary File

Implements an iterable file format that handles the
RADIUS ``$INCLUDE`` directives behind the scene.

``$INCLUDE`` resolution is sandboxed to a base directory so a malicious
or sloppy dictionary can't pull in ``/etc/passwd`` or escape via
``../../``. The base directory defaults to the directory of the
entry-point file (or ``os.curdir`` when the entry-point is a stream).
Pass ``include_base_dir`` to ``DictFile`` or ``Dictionary`` to lock
includes to an explicit trusted root.
"""

import io
import os
from typing import Optional, Self

from pyrad2.exceptions import ParseError


class _Node:
    """Dictionary file node

    A single dictionary file.
    """

    __slots__ = ("name", "lines", "current", "length", "dir")

    def __init__(self, fd: io.TextIOWrapper, name: str, parentdir: str):
        self.lines = fd.readlines()
        self.length = len(self.lines)
        self.current = 0
        self.name = os.path.basename(name)
        path = os.path.dirname(name)
        if os.path.isabs(path):
            self.dir = path
        else:
            self.dir = os.path.join(parentdir, path)

    def next(self) -> Optional[str]:
        if self.current >= self.length:
            return None
        self.current += 1
        return self.lines[self.current - 1]


class DictFile:
    """Dictionary file class

    An iterable file type that handles ``$INCLUDE`` directives
    internally. ``$INCLUDE`` paths are confined to ``include_base_dir``
    so a malicious dictionary can't read arbitrary files.
    """

    __slots__ = ("stack", "_include_base")

    def __init__(
        self,
        fil: str | io.TextIOWrapper,
        *,
        include_base_dir: Optional[str] = None,
    ) -> None:
        """Initialize the file reader and queue ``fil`` for iteration.

        Args:
            fil: A dictionary file path or an already-open text stream.
            include_base_dir: Trusted base directory for ``$INCLUDE``
                resolution. Nested includes whose resolved path falls
                outside this directory are rejected with ``ParseError``.
                Defaults to the directory of ``fil`` when it's a path,
                or ``os.curdir`` when it's a stream.
        """
        self.stack: list[_Node] = []
        if include_base_dir is not None:
            self._include_base = os.path.realpath(include_base_dir)
        elif isinstance(fil, str):
            entry_dir = os.path.dirname(os.path.abspath(fil)) or os.curdir
            self._include_base = os.path.realpath(entry_dir)
        else:
            self._include_base = os.path.realpath(os.curdir)
        self.__read_node(fil, is_entry_point=True)

    def __read_node(
        self, fil: str | io.TextIOWrapper, *, is_entry_point: bool = False
    ) -> None:
        parentdir = self.__cur_dir()
        if isinstance(fil, str):
            if os.path.isabs(fil):
                fname = fil
            else:
                fname = os.path.join(parentdir, fil)
            # Nested ``$INCLUDE`` paths are sandboxed; the entry-point
            # file is exempt because it implicitly defines the base.
            if not is_entry_point:
                resolved = os.path.realpath(fname)
                try:
                    common = os.path.commonpath([self._include_base, resolved])
                except ValueError:
                    common = ""
                if common != self._include_base:
                    raise ParseError(
                        "$INCLUDE %r escapes the dictionary base directory %r"
                        % (fil, self._include_base),
                        file=self.file(),
                        line=self.line(),
                    )
            # ``with`` so a parser error inside ``_Node.__init__`` doesn't
            # leak the file descriptor.
            with open(fname) as fd:
                node = _Node(fd, fil, parentdir)
        else:
            node = _Node(fil, "", parentdir)
        self.stack.append(node)

    def __cur_dir(self) -> str:
        if self.stack:
            return self.stack[-1].dir
        else:
            return os.path.realpath(os.curdir)

    def __get_include(self, line: str) -> Optional[str]:
        line = line.split("#", 1)[0].strip()
        tokens = line.split()
        if tokens and tokens[0].upper() == "$INCLUDE":
            return " ".join(tokens[1:])
        else:
            return None

    def line(self) -> int:
        """Returns line number of current file"""
        if self.stack:
            return self.stack[-1].current
        else:
            return -1

    def file(self) -> str:
        """Returns name of current file"""
        if self.stack:
            return self.stack[-1].name
        else:
            return ""

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> str:
        while self.stack:
            line = self.stack[-1].next()
            if line is None:
                self.stack.pop()
            else:
                inc = self.__get_include(line)
                if inc:
                    self.__read_node(inc)
                else:
                    return line
        raise StopIteration
