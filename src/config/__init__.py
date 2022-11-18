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

class EvaluationDescription(BaseModel):
    issue: str
    recommendation: str

def _load(file_path: str) -> Union[dict, None]:
    try:
        raw = yaml.safe_load(
            Path(path.join(str(Path(__file__).parent), file_path)).read_bytes()
        )
        return raw
    except yaml.YAMLError:
        internals.logger.warning(f"Unable to read configuration file: {file_path}")
    return None

# cache to optimise disk I/O
_raw_mitre_attack = _load("mitre_attack_11.2.yaml")
_raw_pci3 = _load("pci_dss_3.2.1.yaml")
_raw_pci4 = _load("pci_dss_4.0.yaml")
_rules = _load("rule_desc.yaml")

def get_mitre_attack() -> Union[MitreAttack, None]:
    if not _raw_mitre_attack:
        return None
    return MitreAttack(**_raw_mitre_attack)

def get_pci_dss(version: str = '4.0') -> Union[PCIDSS, None]:
    if version == '4.0' and _raw_pci4:
        return PCIDSS(**_raw_pci4)
    if version == '3.2.1' and _raw_pci3:
        return PCIDSS(**_raw_pci3)
    return None

def get_rule_desc(evaluation_id: str, default: str = 'No additional information available, see the provided references.') -> str:
    if not _rules:
        return default
    return _rules.get(evaluation_id, {}).get('issue', default)

def get_rule_recommendation(evaluation_id: str, default: str = 'TBA') -> str:
    if not _rules:
        return default
    return _rules.get(evaluation_id, {}).get('recommendation', default)

# helper loaders
mitre_attack = get_mitre_attack()
pcidss4 = get_pci_dss('4.0')
pcidss3 = get_pci_dss('3.2.1')
