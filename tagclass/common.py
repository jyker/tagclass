from pathlib import Path
from typing import NewType

# typing
Tag = NewType('Tag', str)
Engine = NewType('Engine', str)
Label = NewType('Label', str)
Hash = NewType('Hash', str)

# path
DataPath = Path(__file__).parent / "data"
FamilyVocPath = DataPath / 'family_voc.toml'
LocatorVocPath = DataPath / 'locator_voc.toml'
ModifierVocPath = DataPath / 'modifier_voc.toml'
VocPathList = [LocatorVocPath, FamilyVocPath, ModifierVocPath]

# initial for test
InitModifierVocPath = DataPath / 'init_modifier.toml'
InitLocatorVocPath = DataPath / 'init_locator.toml'

# tagcerts
TagCertsPath = DataPath / 'tag_certs.toml'
FamCertsPath = DataPath / 'fam_certs.toml'

# maxscore
MaxScore = 100