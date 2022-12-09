from __future__ import annotations
import sys
import toml
from pathlib import Path
from collections import Counter
from typing import Dict, Iterator, List, Set, Tuple
from .common import MaxScore, FamilyVocPath, Tag, VocPathList
from .utils import majority


class TagRoot:
    # for parsing
    behavior = 'behavior'
    platform = 'platform'
    family = 'family'
    method = 'method'
    modifier = 'modifier'
    outofvoc = 'outofvoc'

    def keys(self):
        return [i for i in self.__dict__ if not i.startswith("_")]


class TagState:
    pending = '0'
    confirmed = '1'
    locked = '2'
    aliased = '3'


class TagChar:
    hypen = '-'
    undercore = '_'
    whitespace = ' \t\n\r\v\f'
    ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
    ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    ascii_letters = ascii_lowercase + ascii_uppercase
    digits = '0123456789'
    hexdigits = digits + 'abcdef' + 'ABCDEF'
    octdigits = '01234567'
    punctuation = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
    printable = digits + ascii_letters + punctuation + whitespace
    # default tagchar
    default = ascii_letters + digits
    # gen
    gen = 'gen'


class TagVoc:
    __slots__ = [
        'name', 'root', 'path', 'alias', 'state', 'remark', 'abspath', 'score'
    ]

    def __init__(self,
                 name: Tag,
                 *,
                 root: str = '',
                 path: str = '',
                 alias: str = '',
                 remark: str = '',
                 score: int = 0,
                 state: str = TagState.pending):
        self.name = name
        self.root = root
        self.path = path
        self.alias = alias
        self.state = state
        self.remark = remark
        self.score = score
        self.__post_init__()

    def __post_init__(self):
        # score
        if self.state != TagState.pending:
            self.score = MaxScore
        # abspath
        if self.state == TagState.aliased:
            uuid = self.alias
        else:
            uuid = self.name
        self.abspath = Path(f'/{self.root}') / self.path / uuid

    def __hash__(self) -> int:
        return hash(self.name)

    def __getitem__(self, key):
        return getattr(self, key)

    def __str__(self) -> str:
        return f"{self.name} : {self.abspath}"

    def __repr__(self) -> str:
        return f"{self.name} : {self.abspath}"

    def generic(self) -> bool:
        if self.root == TagRoot.modifier:
            return True
        if 'gen' in self.abspath.parts:
            return True
        return False

    def packeric(self) -> bool:
        if 'packed' in self.abspath.parts:
            return True
        # else
        return False

    def genpackeric(self) -> bool:
        if self.generic() or self.packeric():
            return True
        return False

    def pending(self) -> bool:
        return self.state == TagState.pending

    def aliased(self) -> bool:
        return self.state == TagState.aliased

    def locked(self) -> bool:
        return self.state == TagState.locked

    def update(self, **kwargs) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)
        self.__post_init__()

    def uuid(self) -> str:
        return self.abspath.name

    def asdict(self) -> Dict[str, str]:
        return {k: self[k] for k in self.__slots__}

    def dump(self) -> Dict[str, str]:
        keys = ['root', 'path', 'alias', 'state', 'remark']
        data = self.asdict()
        return {k: data[k] for k in keys if data[k]}

    def listalias(self) -> List[Tag]:
        if self.aliased():
            return []
        if not self.alias:
            return []
        return [i.strip() for i in self.alias.split(';') if i]

    def newalias(self, tag: Tag):
        if not self.alias:
            self.alias = tag
        else:
            self.alias = ';'.join([self.alias, tag])

    def aliaslike(self, name: str) -> TagVoc:
        return TagVoc(name,
                      root=self.root,
                      path=self.path,
                      alias=self.name,
                      state=TagState.aliased)


def unfold_tagvoc(tag: TagVoc) -> List[TagVoc]:
    if not tag.alias:
        return [tag]
    data = [tag]
    for name in tag.alias.split(";"):
        data.append(tag.aliaslike(name))
    return data


def loadvoc(voc_path_list: List[Path],
            ignore_pending: bool = False) -> Dict[Tag, TagVoc]:
    voc = {}
    for voc_path in voc_path_list:
        with open(voc_path, "r") as f:
            data = toml.load(f)
        for k, v in data.items():
            t = TagVoc(k, **v)
            if t.state == TagState.pending:
                if ignore_pending:
                    continue
                else:
                    print(f"[x] {t} is not confirmed")
                    sys.exit(-1)
            # unfold
            tagvoc_list = unfold_tagvoc(t)
            for tagvoc in tagvoc_list:
                # not exist
                if tagvoc.name not in voc:
                    voc[tagvoc.name] = tagvoc
                    continue
                # exist
                exist = voc[tagvoc.name]
                print(f"[x] duplicate {tagvoc} | {exist}")
                sys.exit(-1)
    return voc


def dumpvoc(tagvoc: Dict[Tag, TagVoc],
            root_list: List[str],
            voc_path: Path,
            sort: bool = False) -> None:
    data = {}
    for k, v in tagvoc.items():
        if v.root not in root_list:
            continue
        if v.state == TagState.aliased:
            continue
        data[k] = v.dump()
    if sort:
        data = {
            k: v
            for k, v in sorted(data.items(),
                               key=lambda x: [x[1]['root'], x[0]])
        }
    with open(voc_path, "w") as f:
        toml.dump(data, f)


def lsvoc(tagvoc: Dict[Tag, TagVoc]) -> Dict[str, int]:
    return dict(Counter([t.root for _, t in tagvoc.items()]))


class Vocabulary:
    '''Dict[Tag, TagVoc]
    '''
    __slots__ = ['value']

    def __init__(self,
                 vocpaths: List[Path] = None,
                 ignore_pending: bool = False) -> None:
        if vocpaths is None:
            self.value = {}
        else:
            self.value = loadvoc(vocpaths, ignore_pending=ignore_pending)

    def __len__(self):
        return len(self.value)

    def __getitem__(self, tag: Tag) -> TagVoc:
        return self.value[tag]

    def __repr__(self) -> str:
        return f"Vocabulary : {lsvoc(self.value)}"

    def __str__(self) -> str:
        return f"Vocabulary : {lsvoc(self.value)}"

    def hit(self, tag: Tag) -> bool:
        return tag in self.value

    def get(self, tag: Tag) -> TagVoc:
        return self.value.get(tag, TagVoc(tag, root=TagRoot.outofvoc))

    def is_type(self, tag: Tag) -> bool:
        return self.get(tag).root == TagRoot.behavior

    def is_family(self, tag: Tag) -> bool:
        return self.get(tag).root == TagRoot.family

    def add(self, tag: Tag, **kwargs) -> TagVoc:
        if tag in self.value:
            return self.value[tag]
        # add
        t = TagVoc(tag, **kwargs)
        self.value[tag] = t
        return t

    def delete(self, tag: Tag) -> bool:
        if tag not in self.value:
            return True

        t = self.value[tag]
        if t.state == TagState.locked:
            return False
        else:
            del self.value[tag]
            return True

    def update(self, tag: Tag, **kwargs) -> TagVoc:
        # add not exist
        if tag not in self.value:
            return self.add(tag, **kwargs)
        # exist
        t = self.value[tag]
        # locked tagvoc prohibit to update
        if t.state == TagState.locked:
            return t
        # confirmed tagvoc prohibit to update <root> and <remark>
        if t.state == TagState.confirmed:
            for k in ['root', 'remark']:
                if k in kwargs:
                    del kwargs[k]
        # update
        t.update(**kwargs)
        return t

    def dump(self,
             root_list: List[str],
             voc_path: Path,
             sort: bool = False) -> None:
        dumpvoc(self.value, root_list, voc_path, sort)
