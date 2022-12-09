import json
from pathlib import Path
from tagclass.parse import TagParse
from tagclass.tag import Vocabulary
from tagclass.tokenize import Tokenize
from tagclass.common import InitLocatorVocPath, InitModifierVocPath
from typing import Dict

voc = Vocabulary([InitLocatorVocPath, InitModifierVocPath])
tokenize = Tokenize()
tagparse = TagParse(tokenize)
DataPath = Path(__file__).parent / "data"


def assert_parse(result: Dict, gt: Dict):
    for k, v in gt.items():
        assert result[k] == v


def test_parse():
    engine = 'Microsoft'
    labels = [
        'Backdoor:Win32/Darkshell', 'Dropper:Win32/Agent', 'backdoor/androidos'
    ]
    gts = [{
        'behavior': 'backdoor',
        'platform': 'win',
        'family': 'darkshell'
    }, {
        'behavior': 'dropper',
        'platform': 'win',
        'family': ''
    }, {
        'behavior': 'backdoor',
        'platform': 'androidos',
    }]
    for lb, gt in zip(labels, gts):
        result = tagparse.parse(lb, engine, voc, uniform=False)
        assert_parse(result, gt)


def test_parse_ignore_gen():
    engine = 'Microsoft'
    labels = [
        'Malware:Backdoor:Win32/Darkshell',
    ]
    gts = [{'behavior': 'backdoor', 'platform': 'win', 'family': 'darkshell'}]
    for lb, gt in zip(labels, gts):
        result = tagparse.parse(lb, engine, voc, ignore_gen=True)
        assert_parse(result, gt)