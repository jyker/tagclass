'''Label patter-recognizable anti-malware engines'''
from typing import NewType, Dict

from pyparsing import (ParserElement, Word, Optional, Suppress, ZeroOrMore,
                       Group)

# typing
Tag = NewType('Tag', str)
Label = NewType('Label', str)
Class = NewType('Class', str)

# change to Suppress
ParserElement.inlineLiteralsUsing(Suppress)


# tagchar
class TagChar:
    ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
    ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    digits = '0123456789'
    alpha_digits = ascii_lowercase + ascii_uppercase + digits
    supress = './:!'
    hyphen = '-'
    underscore = '_'


TagWord = Word(TagChar.alpha_digits)
Type = TagWord('behavior')
Platform = TagWord('platform')
Family = TagWord('family')
Variant = TagWord('variant')
Prefix = TagWord('prefix')
Suffix = TagWord('suffix')

# def compose_pattern(pattern_string: str):

# class LabelPattern:
#     engine: str = 'ABC'
#     pattern: str = 'ABC'
#     hyphen_in_char: bool = False
#     underscore_in_char: bool = False
#     tagchar: str = TagChar.alpha_digits

#     cite: str = 'ABC'

#     def __init__(self):
#         # tagchar
#         if self.hyphen_in_char:
#             self.tagchar += TagChar.hyphen
#         if self.underscore_in_char:
#             self.tagchar += TagChar.underscore
#         # tagword
#         tagword = Word(self.tagchar)

#     @staticmethod
#     def setup_pattern(pattern_string: str, tagword: Word):
#         """compose label pattern

#         Parameters
#         ----------
#         pattern_string : str
#             `example:`
#                 [Prefix:]Type.Platform.Family[.Variant]

#             `[]` means Optional,
#             `Type`: key, starts with title, followed by ascii_lowercase
#             `punctuation`: Suppress

#         tagword : Word
#             pyparsing.Word

#         Returns
#         -------
#         pyparsing.Word
#         """
#         meta_char = TagChar.alpha_digits + TagChar.supress
#         meta = (Group(ZeroOrMore('[' + Word(meta_char) + ']')) +
#                 Word(meta_char) +
#                 Group(ZeroOrMore('[' + Word(meta_char) + ']')))

# class Kaspersky(LabelPattern):
#     engine = 'Kaspersky'
#     pattern = '[Prefix:]Type.Platform.Family[.Variant]'

#     cite = 'https://encyclopedia.kaspersky.com/knowledge/rules-for-naming'


def microsoft(label: Label) -> Dict[Class, Tag]:
    '''
    https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/malware-naming?view=o365-worldwide

    Type:Platform/Family[.Variant][!Suffix]
    '''
    hypen_underscore = ['-', '_']

    for k in hypen_underscore:
        label = label.replace(k, '')

    pattern = (Type + ':' + Platform + '/' + Family + Optional('.' + Variant) +
               Optional('!' + Suffix))

    return pattern.parse_string(label, parse_all=True).as_dict()


def kaspersky(label: Label) -> Dict[Class, Tag]:
    '''
    https://encyclopedia.kaspersky.com/knowledge/rules-for-naming/

    [Prefix:]Type.Platform.Family[.Variant]
    '''
    hypen_underscore = ['-', '_']

    for k in hypen_underscore:
        label = label.replace(k, '')

    pattern = (Optional(Prefix + ':') + Type + '.' + Platform + '.' + Family +
               Optional('.' + Variant))

    return pattern.parse_string(label, parse_all=True).as_dict()
