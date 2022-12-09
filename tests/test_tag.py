from pathlib import Path
from tagclass.tag import (unfold_tagvoc, TagState, TagVoc, Vocabulary)

TestVocPath = Path(__file__).parent / "data" / "testvoc.toml"


def test_unfold_tagvoc():
    tag = TagVoc('gen',
                 root='behavior',
                 path='gen',
                 alias='gena;genb',
                 state=TagState.locked)
    tag_list = unfold_tagvoc(tag)
    assert len(tag_list) == 3
    assert tag_list[1].name == 'gena'
    assert tag_list[1].uuid() == 'gen'
    assert str(tag_list[1].abspath) == '/behavior/gen/gen'
    assert tag_list[2].name == 'genb'
    assert tag_list[2].state == TagState.aliased


def test_vocab():
    voc = Vocabulary([TestVocPath])
    assert len(voc) == 3
    assert [i for i in voc.value] == ['worm', 'ransomware', 'ransom']
    assert voc['worm'].root == 'behavior'
    voc.add('gen', root='behavior', path='gen')
    assert voc.hit('gen')
    assert voc['ransom'].state == TagState.aliased
