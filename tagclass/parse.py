from typing import List, Tuple, Dict
from dataclasses import dataclass, field
from .tokenize import Tokenize
from .common import MaxScore, Tag, Engine, Label
from .tag import (Vocabulary, TagChar, TagRoot)

Locators = [TagRoot.behavior, TagRoot.platform, TagRoot.method]


@dataclass
class ParseResult:
    behavior: List[str] = field(default_factory=list)
    platform: List[str] = field(default_factory=list)
    method: List[str] = field(default_factory=list)
    modifier: List[str] = field(default_factory=list)
    score: int = 0
    family: str = ''
    engine: str = ''
    label: str = ''

    def __getitem__(self, key):
        value = getattr(self, key)
        if isinstance(value, list):
            value = ";".join(dict.fromkeys(value))
        return value

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def asdict(self):
        keys = ['behavior', 'platform', 'family', 'method', 'modifier']
        return {k: self[k] for k in keys if self[k]}

    def __str__(self) -> str:
        return str(self.asdict())

    def __repr__(self) -> str:
        return str(self.asdict())


def filepath_like(label: Label) -> bool:
    # \sav6\work_channel1_12\57745154
    # /sav6/work_channel1_12/57745154
    if label.count('/') > 2:
        return True
    if label.count('\\') > 0:
        return True

    return False


def is_valid_label(label: Label) -> bool:
    # check none
    if label is None:
        return False
    # check len
    if len(label) < 3:
        return False
    # check filepath-like
    if filepath_like(label):
        return False
    # others
    return True


def digit_ratio(tag: str) -> float:
    tag_len = len(tag)
    if tag_len == 0:
        return 1.0

    count = sum(c.isdigit() for c in tag)
    return count / tag_len


def is_valid_family(parsed: ParseResult) -> bool:
    '''A temporary patch to filter modifier->family'''
    # todo: add module to filter ``single'' modifier

    # 0. digit_ratio
    if digit_ratio(parsed.family) >= 0.5:
        return False

    # 1. Tencet Title(4) end <Win64.Trojan.Inject.Eawu>
    if parsed.engine == 'Tencent' and len(parsed.family) == 4:
        last_tag = parsed.label.rsplit('.', 1)[-1]
        if last_tag.istitle() and last_tag.lower() == parsed.family:
            return False
    # 2. Cyren Uppercase <W32/Trojan.ZTSA-8671>
    if parsed.engine == 'Cyren' and parsed.family.upper() in parsed.label:
        # last_tag = parsed.label.rsplit('.', 1)[-1]
        # if '-' in last_tag and last_tag.split('-')[-1].isdigit():
        # return False
        return False
    # 3. Uppercase(4) end
    LastUpper4Engines = ['Sophos', 'F-Prot']
    if parsed.engine in LastUpper4Engines and len(parsed.family) == 4:
        last_tag = parsed.label.rsplit('.', 1)[-1]
        if parsed.family.upper() == last_tag:
            return False

    return True


def remove_duplicate_label(
        engine_label: Dict[Engine, Label]) -> Dict[Label, Engine]:
    data = {}
    for engine, label in engine_label.items():
        # === Folllowing rule is from AVClass, thanks their job === #
        # Emsisoft uses same label as
        # GData/ESET-NOD32/BitDefender/Ad-Aware/MicroWorld-eScan,
        # but suffixes ' (B)' to their label. Remove the suffix.
        if label.endswith(' (B)'):
            label = label[:-4]
        # F-Secure uses Avira's engine since Nov. 2018
        # but prefixes 'Malware.' to Avira's label. Remove the prefix.
        if label.startswith('Malware.'):
            label = label[8:]
        # ========================================================== #
        if len(label) == 0:
            continue
        if label is None:
            continue
        # save max engine label
        if label not in data:
            data[label] = engine
        elif engine > data[label]:
            data[label] = engine
    # return
    return data


class RunMode:
    parse = 'parsing'
    update = 'updating'


class TagParse:
    locaters = [TagRoot.behavior, TagRoot.platform, TagRoot.method]

    def __init__(self, tokenize: Tokenize, mode: str = RunMode.parse) -> None:
        self.tokenize = tokenize
        self.mode = mode

    def cfs(self, engine: Engine, label: Label,
            voc: Vocabulary) -> Tuple[Tag, List[Tag]]:
        '''Cooccurence Fist Search
        search potential locator tags by <family, locator> cooccurence
        '''
        tag_sequence = self.tokenize.run(engine, label)
        for tag in tag_sequence:
            tagvoc = voc.get(tag)
            if tagvoc.root == TagRoot.family:
                return tag, [i for i in tag_sequence if i != tag]
        return '', []

    def lfs(self, tag_seq: List[Tag], result: ParseResult, voc: Vocabulary,
            uniform: bool, ignore_gen: bool) -> ParseResult:
        '''Location First Search
        search family tag in the context of locator tags.
        '''
        mark = 0
        potential = []
        for i, t in enumerate(tag_seq):
            tagvoc = voc.get(t)
            name = tagvoc.uuid() if uniform else tagvoc.name
            root = tagvoc.root
            # oov
            if root == TagRoot.outofvoc:
                potential.append(t)
                continue
            # locator
            if root in Locators:
                potential.append(mark)
            # ignore generic tags
            if ignore_gen and tagvoc.genpackeric():
                continue
            # save result
            if root == TagRoot.behavior:
                result.behavior.append(name)
            elif root == TagRoot.platform:
                result.platform.append(name)
            elif root == TagRoot.method:
                result.method.append(name)
            elif root == TagRoot.modifier:
                result.modifier.append(name)
            elif root == TagRoot.family:
                if not result.family:
                    result.family = name
            else:
                raise ValueError(f'Invalid root = {root}')
        # hit family in the vocabulary
        if result.family:
            result.score = MaxScore
            return result

        score = sum([1 for i in potential if i == mark])
        # all locator
        if score == len(potential):
            return result
        # no locator
        if score == 0:
            if self.mode == RunMode.parse:
                result.family = potential[0]
            return result

        # location first search
        locations = [i for i, j in enumerate(potential) if j == mark]
        first, last = locations[0], locations[-1]
        bound = len(potential) - 1
        # 1-continous
        if len(potential[first:last + 1]) == score:
            if first == 0 and last < bound:
                result.family = potential[last + 1]
            else:
                result.family = potential[first - 1]
        # 2-discontinous
        else:
            for i in range(first + 1, last):
                if potential[i] != mark:
                    result.family = potential[i]
                    break
        # updating mode
        if self.mode == RunMode.update and score <= 1:
            result.family = ''
        # return
        return result

    def parse(self,
              label: Label,
              engine: Engine,
              voc: Vocabulary,
              uniform: bool = True,
              ignore_gen: bool = False) -> ParseResult:
        # init ParseResult
        result = ParseResult(engine=engine, label=label)
        if not is_valid_label(label):
            return result
        # tokenize
        tag_seq = self.tokenize.run(engine, label)
        # location first search
        result = self.lfs(tag_seq, result, voc, uniform, ignore_gen)
        if not is_valid_family(result):
            result.family = ''
        # uniform
        return result