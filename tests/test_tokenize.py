from tagclass.tokenize import Tokenize


def test_tokenize():
    tokenize = Tokenize()

    engine = 'Microsoft'
    label = 'Worm:Win32/Silly.Gaa'
    expect = ['worm', 'win', 'silly']
    assert tokenize.run(engine, label) == expect

    label = 'Worm:Win32/Silly_12a23b'
    expect = ['worm', 'win', 'silly', '12a23b']
    assert tokenize.run(engine, label) == expect

    label = 'Trojan.Emotet!8.B95 (TFE:3:8TNkkv9OZTL)'
    engine = 'Rising'
    expect = ['trojan', 'emotet']
    assert tokenize.run(engine, label) == expect