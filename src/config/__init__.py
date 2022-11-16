import logging
from os import path
from pathlib import Path
from typing import Union, Optional

import yaml
from pydantic import BaseModel, HttpUrl

import internals

logger = logging.getLogger(__name__)

def force_keys_as_str(self, node, deep=False):
    data = self.old_construct_mapping(node, deep)
    return {
        (str(key) if isinstance(key, (int, float)) else key): data[key] for key in data
    }


yaml.SafeLoader.old_construct_mapping = yaml.SafeLoader.construct_mapping
yaml.SafeLoader.construct_mapping = force_keys_as_str

class MitreAttackTactic(BaseModel):
    id: str
    name: str
    description: str

class MitreAttackMitigations(BaseModel):
    id: str
    name: str
    description: str

class MitreAttackDataSources(BaseModel):
    id: str
    name: str
    description: str

class MitreAttackSubTechniques(BaseModel):
    id: str
    name: str
    description: str

class MitreAttackTechniques(BaseModel):
    id: str
    name: str
    description: str
    sub_techniques: Optional[list[MitreAttackSubTechniques]]

class MitreAttack(BaseModel):
    version: str
    tactics_base_url: HttpUrl
    tactics: list[MitreAttackTactic]
    mitigations_base_url: HttpUrl
    mitigations: list[MitreAttackMitigations]
    data_sources_base_url: HttpUrl
    data_sources: list[MitreAttackDataSources]
    techniques_base_url: HttpUrl
    techniques: list[MitreAttackTechniques]

class PCIDSS(BaseModel):
    version: str
    requirements: dict[str, str]

def _load(file_path: str) -> Union[dict, None]:
    try:
        raw = yaml.safe_load(
            Path(path.join(str(Path(__file__).parent), file_path)).read_bytes()
        )
        return raw
    except yaml.YAMLError:
        internals.logger.warning(f"Unable to read configuration file: {file_path}")
    return None


def _mitre_attack() -> Union[MitreAttack, None]:
    data = _load("mitre_attack_11.2.yaml")
    if not data:
        return None
    return MitreAttack(**data)

def _pci_dss(version: str = '4.0') -> Union[PCIDSS, None]:
    data = _load(f"pci_dss_{version}.yaml")
    if not data:
        return None
    return PCIDSS(**data)

mitre_attack = _mitre_attack()
pcidss4 = _pci_dss('4.0')
pcidss3 = _pci_dss('3.2.1')
