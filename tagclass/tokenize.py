import re
from typing import List
from tagclass.tag import TagChar
from tagclass.common import Tag, Engine, Label

LastDotRemoveEngine = {
    # ===
    'avast',
    'avira',
    'comodo',
    'eset-nod32',
    'fortinet',
    'gdata',
    'jiangmin',
    'kaspersky',
    'microsoft',
    'nano-antivirus',
    'norman',
    'sophos',
    'trendmicro',
    'trendmicro-housecall',
    # ===
    'avg',
    'alibaba',
}

LastSeparatorRemove = ['@', '#', '!']


def remove_suffixes(engine: Engine, label: Label) -> Label:
    '''Remove label suffix
    '''
    # remove engine-specific last  '.'
    if engine in LastDotRemoveEngine:
        label = label.rsplit('.', 1)[0]
    # remove specific separator
    for sep in LastSeparatorRemove:
        label = label.rsplit(sep, 1)[0]

    return label


def uniform_name(engine: Engine) -> Engine:
    return engine.lower().replace(' ', '')


def hasdigit(tag: Tag) -> bool:
    return any(c.isdigit() for c in tag)


class Tokenize:

    def separator(self, engine: Engine) -> str:
        # todo: engine-specific separator
        return "[^a-zA-Z0-9]"

    def run(self, engine: Engine, label: Label) -> List[Tag]:
        engine = uniform_name(engine)
        # suffix remove
        label = remove_suffixes(engine, label)
        # tokenize
        sep = self.separator(engine)
        tag_list = []
        for tag in re.split(sep, label):
            # 1.ignore not str
            if not isinstance(tag, str):
                continue
            # 2. ignore pure digits
            if tag.isdigit():
                continue
            # 3. ignore digits + ascii_uppercase
            if hasdigit(tag) and tag.isupper():
                continue
            # 4. remove suffix digits
            tag = tag.rstrip(TagChar.digits)
            # 5. check length
            if len(tag) < 3:
                continue
            # append lower
            tag_list.append(tag.lower())

        return tag_list
