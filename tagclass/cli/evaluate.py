import typer
import json
import toml
from pathlib import Path
from rich import print
from rich.progress import track
from typing import Dict, Set, Tuple
from collections import defaultdict
from tagclass.tokenize import Tokenize
from tagclass.update import locator_incremental_update
from tagclass.parse import TagParse, Locators, RunMode, ParseResult
from tagclass.tag import Vocabulary, TagChar, TagState
from tagclass.common import (InitModifierVocPath, Tag, Label, Engine,
                             InitLocatorVocPath)

app = typer.Typer()


def load_labels(apiv2_jsonl: Path) -> Dict[Label, Engine]:
    data = {}
    with open(apiv2_jsonl, 'r') as f:
        for line in track(f, description='Loading labels >>>'):
            scans = json.loads(line.strip())['scans']
            for engine, res in scans.items():
                if res['detected']:
                    label = res['result']
                    # clean
                    label = ''.join(
                        filter(lambda x: x in TagChar.printable,
                               label)).strip()
                    # filter
                    if (label is None) or (len(label) < 3):
                        continue
                    # store
                    data[label] = engine
    return data


def precision_recall(ground: Dict[Tag, int], updated: Set[Tag],
                     initial: Set[Tag], threshold: int):
    # precision focus on updated locator
    y = set(list(ground.keys()))
    tp = y & updated
    # debug
    # print(f'[+] error updated: {updated - y}')
    data = {}
    if len(updated) == 0:
        return {}
    data['precision'] = len(tp) / len(updated)
    # recall focus on all possible locators
    possible = set([k for k, v in ground.items() if v >= threshold])
    tpos = initial.union(tp) & possible
    data['recall'] = len(tpos) / len(possible)
    return data


def load_liu_data(file_path):
    import pandas as pd
    from collections import Counter

    df = pd.read_csv(file_path, dtype=str)
    df = df.fillna('')
    fields = ['behavior', 'platform', 'family', 'modifier', 'method']
    result = {}
    for k in track(fields, description='Loading truth >>>'):
        data = {}
        voc = []
        for i in df[k]:
            if i == '':
                continue
            if ';' not in i:
                voc.append(i)
            else:
                voc.extend([i for i in i.split(';') if i])
        part = sorted(Counter(voc).items(),
                      key=lambda x: (x[1], x[0]),
                      reverse=True)
        for t, c in part:
            data[t] = int(c)
        result[k] = data
    return result


@app.command(short_help='test incremental parsing for locator update')
def update(dataset: str,
           threshold_cfs: int = 2,
           max_round: int = 5,
           dump: bool = False,
           lfs_mode: str = 'updating',
           verbose: int = 0):
    # path
    vtapiv2_path = Path.home(
    ) / f'dataset/{dataset}-space/vtapiv2/{dataset}-vtapiv2.jsonl'
    ground_path = Path.home(
    ) / f'dataset/{dataset}-space/groundtruth/{dataset}-hand-parsing.csv'
    # ground truth
    truth = load_liu_data(ground_path)
    truth_locator = {}
    for k in ['behavior', 'platform', 'method']:
        truth_locator.update(truth[k])
    possible_be_updated_set = set(
        [k for k, v in truth_locator.items() if v >= threshold_cfs])
    # malware labels
    labels = load_labels(vtapiv2_path)
    print(f'[*] {dataset} labels = {len(labels)}')
    # init vocabulary
    init_voc = Vocabulary([InitLocatorVocPath, InitModifierVocPath])
    # loop
    metric = []
    verified = TagState.locked
    pending = TagState.pending
    round = 0
    updated_this_round = 1
    cumulative_updated_set = set()
    while updated_this_round > 0:
        round += 1
        if round > max_round:
            break
        updated_this_round = 0
        print(f'\n========== Locator update round {round} ==========')
        # init
        init_locator_set = set(
            [k for k, v in init_voc.value.items() if v.root in Locators])
        remain_updated_set = possible_be_updated_set - init_locator_set
        print('// initial vocabulary')
        print(f"[*] {init_voc}")
        print('// locators in labels')
        print(f'[*] total = {len(possible_be_updated_set)}')
        print(f'[*] out of initial = {len(remain_updated_set)}')
        # LIU
        print("// LFS-CFS loop until no new locator")
        init_voc = locator_incremental_update(labels,
                                              voc=init_voc,
                                              threshold_cfs=threshold_cfs,
                                              lfs_mode=lfs_mode)
        round_updated_set = set([
            k for k, v in init_voc.value.items()
            if v.root in Locators and v.state == pending
        ])
        updated_this_round = len(round_updated_set)
        # add
        cumulative_updated_set = cumulative_updated_set.union(
            round_updated_set)

        print('// updated')
        print(f'[*] upated = {updated_this_round}')
        if verbose >= 1 and round_updated_set:
            print(round_updated_set)
        # pr
        pre_rec = precision_recall(truth_locator, cumulative_updated_set,
                                   init_locator_set, threshold_cfs)
        print(pre_rec)
        pre_rec['updated'] = updated_this_round
        metric.append(pre_rec)

        # manual verification updated locators
        print(f'// imitating verification')
        for k, data in init_voc.value.items():
            # updated locators
            if data.root not in Locators:
                continue
            if data.state == verified:
                continue
            # verify tag
            data.state = verified
            if k in truth['modifier']:
                data.root = 'modifier'
            elif k in truth['family']:
                data.root = 'family'
            elif k in truth['behavior']:
                data.root = 'behavior'
            elif k in truth['platform']:
                data.root = 'platform'
            elif k in truth['method']:
                data.root = 'method'
            else:
                print(f'[x] {data} out of class')
            # verify remark
            remark = data.remark.split('->')[0].strip()
            if remark in truth['modifier']:
                init_voc.update(remark, root='modifier', state=verified)
            elif remark in truth['family']:
                init_voc.update(remark, root='family', state=verified)
            elif remark in truth['behavior']:
                init_voc.update(remark, root='behavior', state=verified)
            elif remark in truth['platform']:
                init_voc.update(remark, root='platform', state=verified)
            elif remark in truth['method']:
                init_voc.update(remark, root='platform', state=verified)
        # remove pending
        init_voc.value = {
            k: v
            for k, v in init_voc.value.items() if v.state == verified
        }
        # fix cumulative_updated_set
        cumulative_updated_set = {
            i
            for i in cumulative_updated_set if init_voc.get(i).root in Locators
        }
        # dump
        if dump:
            with open(InitLocatorVocPath, 'w') as f:
                locators = {
                    k: v.dump()
                    for k, v in init_voc.value.items() if v.root in Locators
                }
                toml.dump(locators, f)
            with open(InitModifierVocPath, 'w') as f:
                modifiers = {
                    k: v.dump()
                    for k, v in init_voc.value.items() if v.root == 'modifier'
                }
                toml.dump(modifiers, f)
        # failed updated
        failed_update = possible_be_updated_set - set(
            [k for k, v in init_voc.value.items() if v.root in Locators])
        if verbose >= 2 and failed_update:
            print(f'[*] failed updated = {len(failed_update)}')
            print(failed_update)
        print('============================================')
    # report
    failed_update = possible_be_updated_set - set(
        [k for k, v in init_voc.value.items() if v.root in Locators])
    print(f'// report')
    if round <= max_round:
        print(f'[-] LIU finishes at round {round}')

    else:
        print(f'[-] LIU exceeds max round {max_round}')
    print(f'[-] threshold_cfs = {threshold_cfs} | lfs_mode = {lfs_mode}')
    print(
        f'[-] {dataset}: labels = {len(labels)} | locators = {len(possible_be_updated_set)}'
    )
    print(f'[*] failed updated = {len(failed_update)}')
    print('[*] metrics of each round: ')
    print(metric)


@app.command(short_help='test CFS threshold')
def threshold(dataset: str = 'motif',
              max_threshold: int = 16,
              max_round: int = 5,
              lfs_mode: str = 'updating'):
    # path
    vtapiv2_path = Path.home(
    ) / f'dataset/{dataset}-space/vtapiv2/{dataset}-vtapiv2.jsonl'
    ground_path = Path.home(
    ) / f'dataset/{dataset}-space/groundtruth/{dataset}-hand-parsing.csv'
    # ground truth
    truth = load_liu_data(ground_path)
    truth_locator = {}
    for k in ['behavior', 'platform', 'method']:
        truth_locator.update(truth[k])
    # malware labels
    labels = load_labels(vtapiv2_path)
    print(f'[*] {dataset} labels = {len(labels)}')

    record = {}
    for threshold in range(2, max_threshold + 1):
        print(f'========== threshold_cfs = {threshold} ==========')
        # init vocabulary
        init_voc = Vocabulary([InitLocatorVocPath, InitModifierVocPath])
        # possible_be_updated
        possible_be_updated_set = set(
            [k for k, v in truth_locator.items() if v >= threshold])
        # loop
        metric = []
        verified = TagState.locked
        pending = TagState.pending
        round = 0
        updated_this_round = 1
        cumulative_updated_set = set()
        while updated_this_round > 0:
            round += 1
            if round >= max_round:
                break
            updated_this_round = 0
            # init
            init_locator: Dict[Tag, TagVoc] = {}
            init_modifier: Dict[Tag, TagVoc] = {}
            init_family: Dict[Tag, TagVoc] = {}
            for k, v in init_voc.value.items():
                if v.root in Locators:
                    init_locator[k] = v
                elif v.root == 'modifier':
                    init_modifier[k] = v
                elif v.root == 'family':
                    init_family[k] = v
            init_locator_set = set(list(init_locator.keys()))
            # LIU
            init_voc = locator_incremental_update(labels,
                                                  voc=init_voc,
                                                  threshold_cfs=threshold,
                                                  lfs_mode=lfs_mode,
                                                  verbose=0)
            round_updated_set = set([
                k for k, v in init_voc.value.items()
                if v.root in Locators and v.state == pending
            ])
            updated_this_round = len(round_updated_set)
            # add
            cumulative_updated_set = cumulative_updated_set.union(
                round_updated_set)
            # pr
            pre_rec = precision_recall(truth_locator, cumulative_updated_set,
                                       init_locator_set, threshold)
            pre_rec['updated'] = updated_this_round
            metric.append(pre_rec)

            # manual verification updated locators
            for k, data in init_voc.value.items():
                # updated locators
                if data.root not in Locators:
                    continue
                if data.state == verified:
                    continue
                # verify tag
                data.state = verified
                if k in truth['modifier']:
                    data.root = 'modifier'
                elif k in truth['family']:
                    data.root = 'family'
                elif k in truth['behavior']:
                    data.root = 'behavior'
                elif k in truth['platform']:
                    data.root = 'platform'
                elif k in truth['method']:
                    data.root = 'method'
                else:
                    print(f'[x] {data} out of class')
                # verify remark
                remark = data.remark.split('->')[0].strip()
                if remark in truth['modifier']:
                    init_voc.update(remark, root='modifier', state=verified)
                elif remark in truth['family']:
                    init_voc.update(remark, root='family', state=verified)
                elif remark in truth['behavior']:
                    init_voc.update(remark, root='behavior', state=verified)
                elif remark in truth['platform']:
                    init_voc.update(remark, root='platform', state=verified)
                elif remark in truth['method']:
                    init_voc.update(remark, root='platform', state=verified)
            # remove pending
            init_voc.value = {
                k: v
                for k, v in init_voc.value.items() if v.state == verified
            }
            # fix cumulative_updated_set
            cumulative_updated_set = {
                i
                for i in cumulative_updated_set
                if init_voc.get(i).root in Locators
            }
        # report
        print(f'// report')
        if round < max_round:
            print(f'[-] LIU finishes at round {round}')

        else:
            print(f'[-] LIU exceeds max round {round}')
        print(f'[-] threshold_cfs = {threshold} | lfs_mode = {lfs_mode}')
        print(
            f'[-] {dataset}: labels = {len(labels)} | locators = {len(possible_be_updated_set)}'
        )
        print('[*] metrics of each round: ')
        print(metric)
        record[threshold] = {'round-1': metric[0], 'final': metric[-1]}
    # records
    print('[*] record of each threshold: ')
    print(record)


def load_lfs_data(ground_truth: Path,
                  threshold_cfs: int = 6) -> Tuple[Vocabulary, Dict]:
    import pandas as pd
    from collections import Counter

    df = pd.read_csv(ground_truth, index_col=[0], dtype=str)
    df = df.fillna('')
    fields = ['behavior', 'platform', 'method']
    voc = Vocabulary([InitModifierVocPath])
    for k in fields:
        for t in df[k]:
            if t == '':
                continue
            t = t.split(';')
            for i in t:
                voc.update(i, root=k, state='2')
    # modifiers with threshold_cfs >= 6 will be verified by the LIU
    # modifiers = [k for k, v in Counter(df['modifier']).items() if v >= 6]
    mod_count = defaultdict(int)
    for _, row in df.iterrows():
        if row['family']:
            for i in row['modifier'].split(';'):
                if i:
                    mod_count[i] += 1
    modifiers = [k for k, v in mod_count.items() if v >= threshold_cfs]
    for t in modifiers:
        voc.update(t, root='modifier', state='2')

    df = df.to_dict(orient='index')
    return voc, df


@app.command(short_help='test location first search for parsing')
def parse(dataset: str, verbose: int = 0):
    # euphony
    euphony_path = Path.home(
    ) / f'git/labgit/fmind-euphony/evaluate/{dataset}/parse-rules.json'
    with open(euphony_path, 'r') as f:
        euphony_result: Dict[str, str] = json.load(f)
    # vtapiv2
    vtapiv2_path = Path.home(
    ) / f'dataset/{dataset}/vtapiv2/{dataset}-vtapiv2.jsonl'
    label_engine = load_labels(vtapiv2_path)
    # ground
    ground_path = Path.home(
    ) / f'dataset/{dataset}/groundtruth/{dataset}-hand-parsing.csv'
    voc, groundtruth = load_lfs_data(ground_path)
    # tagclass
    parser = TagParse(Tokenize(), mode=RunMode.parse)
    tagclass_result: Dict[Label, ParseResult] = {}
    for label, engine in label_engine.items():
        parsed = parser.parse(label, engine=engine, voc=voc, uniform=False)
        label = label.lower()
        if label not in tagclass_result:
            tagclass_result[label] = parsed
        elif label in tagclass_result and parsed.family:
            tagclass_result[label] = parsed

    # euphony scope acc
    scope_acc = defaultdict(list)
    eup1_tag0 = []
    scope_tag0 = []
    eup0 = []
    for label, family in euphony_result.items():
        label = label.strip()
        gt_fam = groundtruth[label]['family']
        eup = gt_fam == family
        tag = gt_fam == tagclass_result[label].family
        scope_acc['euphony'].append(eup)
        scope_acc['tagclass'].append(tag)
        # eup0
        if not eup:
            eup0.append(f'{label} -> {family}')
        # tag0
        if not tag:
            parsed = tagclass_result[label]
            label_origin = parsed.label
            engine = parsed.engine
            parsed = parsed.asdict()
            parsed['label'] = label_origin
            parsed['engine'] = engine
            parsed['truth'] = gt_fam
            scope_tag0.append(parsed)
            if eup:
                eup1_tag0.append(parsed)
    # all acc
    tagclass_acc = []
    tag0 = []
    for label, parsed in tagclass_result.items():
        tag = parsed.family == groundtruth[label]['family']
        tagclass_acc.append(tag)
        if not tag:
            label_origin = parsed.label
            engine = parsed.engine
            parsed = parsed.asdict()
            parsed['label'] = label_origin
            parsed['engine'] = engine
            parsed['truth'] = groundtruth[label]['family']
            tag0.append(parsed)
    # verbose
    if verbose == -1:
        print(f"[*] Euphony failed {len(eup0)}:")
        print(eup0)
    if verbose == 1:
        print(f"[*] Euphony success and Tagclass failed {len(eup1_tag0)}:")
        print(eup1_tag0)
    if verbose == 2:
        print(
            f"[*] Tagclass failed  / Euphony scope {len(scope_tag0)} / {len(euphony_result)}:"
        )
        print(scope_tag0)
    if verbose == 3:
        print(f"[*] Tagclass failed / all  {len(tag0)} / {len(groundtruth)}:")
        print(tag0)
    # summary
    # scope acc
    print(f'''[*] ============ Acc of Euphony scope ============ 
    {dataset} labels = {len(groundtruth)}
    Euphony focus = {len(euphony_result)}
    Euphony success and Tagclass failed = {len(eup1_tag0)}
    Tagclass failed under Euphony scope = {len(scope_tag0)}
    Euphony Acc = {sum(scope_acc['euphony']) / len(scope_acc['euphony'])}
    Tagclass Acc = {sum(scope_acc['tagclass']) / len(scope_acc['tagclass'])}
    =============================================''')
    # all acc
    print(f'''[*] ============= Acc of all labels =============
    {dataset} labels = {len(groundtruth)}
    Tagclass failed  = {len(tag0)}
    Tagclass Acc = {sum(tagclass_acc) / len(tagclass_acc)}
    =============================================''')
