
<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/jyker/tagclass">
  </a>

  <h3 align="center">TagClass</h3>

  <p align="center">
    A Tool for Extracting Class-determined Tags for Massive Malware Labels
    <br />
    <a href="https://github.com/jyker/tagclass"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/jyker/tagclass">View Demo</a>
    ·
    <a href="https://github.com/jyker/tagclass/issues">Report Bug</a>
    ·
    <a href="https://github.com/jyker/tagclass/issues">Request Feature</a>
  </p>
</div>



<!-- ABOUT THE PROJECT -->
## Abstract

VirusTotal is widely used for malware annotation, by providing malware labels from a large set of anti-malware engines. One of the long-standing challenges in using these crowdsourced labels is extracting class-determined tags. 

TagClass is a tool based on incremental parsing to associate tags with their corresponding family, behavior, and platform classes. TagClass treats behavior and platform tags as locators, and achieves incremental parsing by introducing and iterating the following two algorithms: 1) location first search, which hits family tags using locators, and 2) co-occurrence first search, which finds new locators using family tags. 

Experiments across two benchmark datasets indicate TagClass outperforms existing methods, improving the parsing accuracy by 20% and 28%, respectively. To the best of our knowledge, TagClass is the first tag class-determined malware label parsing tool, which would pave the way for research on crowdsourced malware annotation.

<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

TagClass uses [Poetry](https://python-poetry.org/docs/) for dependency management and packaging in Python. Please install it first according to its official documentation.

### Installation

- Run the following commands:
   ```sh
   git clone https://github.com/jyker/tagclass.git
   cd tagclass
   poetry install
   ```



<!-- USAGE EXAMPLES -->
## Usage

- Help
    ```sh
    $ tagclass --help

    Usage: tagclass [OPTIONS] COMMAND [ARGS]...

    ╭─ Options ───────────────────────────────────────────────────────╮
    │ --help          Show this message and exit.                     │
    ╰─────────────────────────────────────────────────────────────────╯
    ╭─ Commands ──────────────────────────────────────────────────────╮
    │ clean          Clean pending vocabulary                         │
    │ evaluate       Evaluation for TagClass                          │
    │ list           List vocabulary                                  │
    │ parse          Location First Search for Parsing                │
    │ tokenize       Tokenize malware label                           │
    │ update         Incremental Parsing for Updating                 │
    │ version        TagClass version                                 │
    ╰─────────────────────────────────────────────────────────────────╯
    ```

- Location first search (LFS) for parsing
    ```sh
    $ tagclass parse Ransom.Win32.Cerber
    {'behavior': 'ransom', 'platform': 'win', 'family': 'cerber'}
   ```
- Evaluation

    ```sh
    $ tagclass evaluate parse malgenome
    Loading labels >>> ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    [*] ============ Acc of Euphony scope ============
        malgenome labels = 6662
        Euphony focus = 4361
        Euphony success and Tagclass failed = 3
        Tagclass failed under Euphony scope = 9
        Euphony Acc = 0.7667966062829626
        Tagclass Acc = 0.9979362531529465
        =============================================
    [*] ============= Acc of all labels =============
        malgenome labels = 6662
        Tagclass failed  = 190
        Tagclass Acc = 0.9714757543912326
        =============================================
    ```


<!-- LICENSE -->
## License

Distributed under the MIT License.