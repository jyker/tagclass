from collections import Counter
from typing import List, Tuple


def counter_tag(tag_list: List[str]) -> List[Tuple[str, int]]:
    num = len(tag_list)
    if num == 0:
        return [('', 0)]
    if num == 1:
        return [(tag_list[0], 1)]

    return sorted(Counter(tag_list).items(),
                  key=lambda x: [x[1], x[0]],
                  reverse=True)


def majority(tag_list: List[str]) -> str:
    return counter_tag(tag_list)[0][0]