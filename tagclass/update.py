from rich import print
from pathlib import Path
from typing import List, Dict
from collections import defaultdict
from .tokenize import Tokenize
from .parse import TagParse, RunMode, Locators
from .tag import Vocabulary
from .common import (LocatorVocPath, MaxScore, VocPathList, Label, Engine,
                     FamilyVocPath)


def cfs(label_engine: Dict[Label, Engine], tagparse: TagParse,
        voc: Vocabulary):
    counter = defaultdict(int)
    remark = {}
    for label, engine in label_engine.items():
        family, result = tagparse.cfs(engine, label, voc)
        if not family:
            continue
        if len(result) == 0:
            continue
        # occurrence along with family tags
        for t in result:
            if not voc.hit(t):
                counter[t] += 1
                remark[t] = f'{family} -> {label}'
    return counter, remark


def lfs(label_engine: Dict[Label, Engine], tagparse: TagParse,
        voc: Vocabulary):
    for label, engine in label_engine.items():
        # pasrse
        result = tagparse.parse(label, engine, voc, uniform=True)
        family = result.family
        # new family
        if family and (result.score != MaxScore):
            voc.update(family,
                       root='family',
                       remark=f"{family} -> {result.label}")
    return voc


def locator_incremental_update(label_engine: Dict[Label, Engine],
                               voc: Vocabulary,
                               threshold_cfs: int = 5,
                               lfs_mode: RunMode = RunMode.update,
                               verbose: int = 1):
    tokenize = Tokenize()
    tagparse = TagParse(tokenize, mode=lfs_mode)
    # step
    step = 1
    loc_new = 1
    while loc_new:
        start_voc = len(voc)
        # === lfs ===
        if verbose:
            print(f'[-] ===== step {step} =====')
        voc = lfs(label_engine, tagparse, voc)
        fam_new = len(voc) - start_voc
        if verbose:
            print(f'[*] LFS: new family = {fam_new}')
        # === cfs ===
        counter, remark = cfs(label_engine, tagparse, voc)
        for tag, coocur in counter.items():
            if coocur >= threshold_cfs:
                voc.update(tag, root='behavior', remark=f"{remark[tag]}")
        # === locator_new ===
        loc_new = len(voc) - start_voc - fam_new
        if verbose:
            print(f'[*] CFS: new locator = {loc_new}')
        step += 1
    # done
    return voc
