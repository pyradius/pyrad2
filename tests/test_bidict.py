import operator

import pytest

from pyrad2.bidict import BiDict


class TestBiDict:
    def setup_method(self):
        self.bidict = BiDict()

    def test_start_empty(self):
        assert len(self.bidict) == 0
        assert len(self.bidict.forward) == 0
        assert len(self.bidict.backward) == 0

    def test_length(self):
        assert len(self.bidict) == 0
        self.bidict.add("from", "to")
        assert len(self.bidict) == 1
        del self.bidict["from"]
        assert len(self.bidict) == 0

    def test_deletion(self):
        with pytest.raises(KeyError):
            operator.delitem(self.bidict, "missing")
        self.bidict.add("missing", "present")
        del self.bidict["missing"]

    def test_backward_deletion(self):
        with pytest.raises(KeyError):
            operator.delitem(self.bidict, "missing")
        self.bidict.add("missing", "present")
        del self.bidict["present"]
        assert self.bidict.has_forward("missing") is False

    def test_forward_access(self):
        self.bidict.add("shake", "vanilla")
        self.bidict.add("pie", "custard")
        assert self.bidict.has_forward("shake") is True
        assert self.bidict.get_forward("shake") == "vanilla"
        assert self.bidict.has_forward("pie") is True
        assert self.bidict.get_forward("pie") == "custard"
        assert self.bidict.has_forward("missing") is False
        with pytest.raises(KeyError):
            self.bidict.get_forward("missing")

    def test_backward_access(self):
        self.bidict.add("shake", "vanilla")
        self.bidict.add("pie", "custard")
        assert self.bidict.has_backward("vanilla") is True
        assert self.bidict.get_backward("vanilla") == "shake"
        assert self.bidict.has_backward("missing") is False
        with pytest.raises(KeyError):
            self.bidict.get_backward("missing")

    def test_item_accessor(self):
        self.bidict.add("shake", "vanilla")
        self.bidict.add("pie", "custard")
        with pytest.raises(KeyError):
            operator.getitem(self.bidict, "missing")
        assert self.bidict["shake"] == "vanilla"
        assert self.bidict["pie"] == "custard"
