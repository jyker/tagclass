import json
import toml
import typer
from pathlib import Path
from rich import print
from rich.progress import track
from typing import Dict
from tagclass.tokenize import Tokenize
from tagclass.tag import Vocabulary, TagChar, TagState
from tagclass.parse import TagParse, Locators
from tagclass.update import locator_incremental_update
from tagclass.common import (FamilyVocPath, LocatorVocPath, ModifierVocPath,
                             VocPathList, Label, Engine)
from tagclass.cli.evaluate import app as evaluate_app
from tagclass import __version__

# ================== CLI ===================
app = typer.Typer(add_completion=False)
app.add_typer(evaluate_app, name="evaluate", help="Evaluation for TagClass")
# ==========================================


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


def load_labels_processed(apiv2_jsonl: Path,
                          transaction: int = None) -> Dict[Label, Engine]:
    data = {}
    count = 0
    with open(apiv2_jsonl, 'r') as f:
        for line in track(f, description='Loading labels >>>'):
            if transaction and count == transaction:
                break
            count += 1
            try:
                scans = json.loads(line.strip())['scans']
            except json.JSONDecodeError:
                continue
            for engine, label in scans.items():
                # clean
                label = ''.join(filter(lambda x: x in TagChar.printable,
                                       label)).strip()
                # filter
                if (label is None) or (len(label) < 3):
                    continue
                # store
                data[label] = engine
    return data


@app.command(short_help='TagClass version')
def version():
    typer.echo(__version__)


@app.command(short_help='List vocabulary')
def list():
    voc = Vocabulary(VocPathList)
    typer.echo(voc)


@app.command(short_help='Clean pending vocabulary')
def clean(voc: str = 'all'):
    typer.echo(f'[-] clean {voc} voc')

    def clean_locator():
        locvoc = Vocabulary([LocatorVocPath], ignore_pending=True)
        locvoc.dump(Locators, LocatorVocPath, sort=True)

    def clean_family():
        locvoc = Vocabulary([LocatorVocPath], ignore_pending=True)
        famvoc = Vocabulary([FamilyVocPath], ignore_pending=True)
        for k, _ in locvoc.value.items():
            if famvoc.hit(k):
                del famvoc.value[k]
        famvoc.dump(['family'], FamilyVocPath, sort=True)

    def clean_modifier():
        locvoc = Vocabulary([LocatorVocPath], ignore_pending=True)
        modvoc = Vocabulary([ModifierVocPath], ignore_pending=True)
        for k, _ in locvoc.value.items():
            if modvoc.hit(k):
                del modvoc.value[k]
        for k, v in modvoc.value.items():
            v.path = ''
        modvoc.dump(['modifier'], ModifierVocPath, sort=True)

    if voc == 'locator':
        clean_locator()
    elif voc == 'family':
        clean_family()
    elif voc == 'modifier':
        clean_modifier()
    else:
        clean_locator()
        clean_family()
        clean_modifier()


@app.command(short_help='Tokenize malware label')
def tokenize(label: str, engine: str = "default"):
    tk = Tokenize()
    print(tk.run(engine, label))


@app.command(short_help='Location First Search for Parsing')
def parse(target: str,
          engine: str = "default",
          uniform: bool = False,
          apiv2: bool = False):
    parser = TagParse(Tokenize())
    voc = Vocabulary(VocPathList)
    if not apiv2:
        result = parser.parse(target, engine, voc, uniform=uniform)
        typer.echo(result)
    else:
        label_engine = load_labels(target)
        result = {}
        for label, engine in track(label_engine.items(),
                                   total=len(label_engine),
                                   description='Parsing ...'):
            result[label] = parser.parse(label, engine, voc,
                                         uniform=uniform).asdict()
        # save
        name = Path(target).stem
        save_path = Path.cwd() / f'{name}-tagclass.json'
        with open(save_path, 'w') as f:
            json.dump(result, f)
        typer.echo(f'[*] saving result in {save_path}')


@app.command(short_help='Incremental Parsing for Updating')
def update(vtapiv2_path: str,
           threshold_cfs: int = 10,
           lfs_mode: str = 'updating',
           max_round: int = 5,
           dump: bool = True,
           transaction: int = None,
           processed: bool = False,
           verbose: int = 0):
    # malware labels
    if processed:
        labels = load_labels_processed(vtapiv2_path, transaction)
    else:
        labels = load_labels(vtapiv2_path)
    print(f'[*] labels = {len(labels)}')
    # init vocabulary
    init_voc = Vocabulary(VocPathList)
    # loop
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
        print('// initial vocabulary')
        print(f"[*] {init_voc}")
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

        # dump
        if dump:
            init_voc.dump(Locators, LocatorVocPath)
    # report
    print(f'// report')
    if round <= max_round:
        print(f'[-] LIU finishes at round {round}')

    else:
        print(f'[-] LIU exceeds max round {max_round}')
    print(f'[-] threshold_cfs = {threshold_cfs} | lfs_mode = {lfs_mode}')


def main():
    app()