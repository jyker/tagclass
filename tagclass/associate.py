import gc
from collections import defaultdict
from itertools import combinations
from typing import Iterator, Set, NewType, Dict, List

AliasRule = NewType('AliasRule', str)
AliasSplit = ';'
Init = 'INIT'


def get_initrule(threshold_cfs: int) -> Dict[AliasRule, int]:
    counter = defaultdict(int)
    counter[Init] = threshold_cfs
    return counter


def get_rule(items: List[str]):
    num = len(items)
    if num < 1:
        raise ValueError('[x] items must be at least 2 elements')
    if num == 1:
        return items[0]
    return ';'.join(sorted(items))


def get_subrule(items: List[str]) -> List[str]:
    num = len(items)
    if num < 1:
        raise ValueError('[x] items must be at least 2 elements')
    if num == 1:
        return [Init]
    if num == 2:
        return [i for i in items]
    sub_items = combinations(sorted(items), num - 1)
    return [';'.join(i) for i in sub_items]


def frequent_rule(
        transaction: Iterator[Set[str]],
        rule_len: int,
        threshold_cfs: int,
        counter: Dict[AliasRule, int] = None) -> Dict[AliasRule, int]:
    # init
    if counter is None and rule_len == 1:
        counter = get_initrule(threshold_cfs)
    # counter
    for tag_set in transaction:
        if len(tag_set) < rule_len:
            continue
        items_list = combinations(tag_set, rule_len)
        for items in items_list:
            # if <rule> is frequent, all <subrule> must be frequent
            valid = True
            for subrule in get_subrule(items):
                if counter[subrule] < threshold_cfs:
                    valid = False
                    break
            if valid:
                counter[get_rule(items)] += 1

    # filter
    pop_rules = [
        rule for rule, freq in counter.items() if freq < threshold_cfs
    ]
    for rule in pop_rules:
        del counter[rule]
    gc.collect()
    # return
    return counter


def detect_alias(transaction: Iterator[Set[str]],
                 threshold_cfs: int = 20,
                 max_len: int = 5) -> Dict[AliasRule, int]:
    # counter
    counter = get_initrule(threshold_cfs)
    for length in range(1, max_len + 1):
        print(f"[-] counter len = {length}")
        counter = frequent_rule(transaction, length, threshold_cfs, counter)
    return counter
