from os import path
from pathlib import Path

import yaml

"""
Takes content in YAML (contributed from the open source CLI project) and generates Markdown files (overwriting markdown changes)
"""

def force_keys_as_str(self, node, deep=False):
    data = self.old_construct_mapping(node, deep)
    return {
        (str(key) if isinstance(key, (int, float)) else key): data[key] for key in data
    }

yaml.SafeLoader.old_construct_mapping = yaml.SafeLoader.construct_mapping
yaml.SafeLoader.construct_mapping = force_keys_as_str

def _load(file_path: str):
    raw = yaml.safe_load(
        Path(path.join(str(Path(__file__).parent), file_path)).read_bytes()
    )
    return raw

for tactic in _load('src/config/mitre_attack_11.2.yaml')['tactics']:
    path_prefix = f'src/config/mitre/attack_11.2/tactics/{tactic["id"]}'
    _handle = Path(path_prefix)
    _handle.mkdir(parents=True, exist_ok=True)
    handle = Path(f'{path_prefix}/{tactic["name"].replace("/", " or ")}.md')
    handle.write_text(tactic["description"], 'utf8')

for mitigation in _load('src/config/mitre_attack_11.2.yaml')['mitigations']:
    path_prefix = f'src/config/mitre/attack_11.2/mitigations/{mitigation["id"]}'
    _handle = Path(path_prefix)
    _handle.mkdir(parents=True, exist_ok=True)
    handle = Path(f'{path_prefix}/{mitigation["name"].replace("/", " or ")}.md')
    handle.write_text(mitigation["description"], 'utf8')

for data_source in _load('src/config/mitre_attack_11.2.yaml')['data_sources']:
    path_prefix = f'src/config/mitre/attack_11.2/data_sources/{data_source["id"]}'
    _handle = Path(path_prefix)
    _handle.mkdir(parents=True, exist_ok=True)
    handle = Path(f'{path_prefix}/{data_source["name"].replace("/", " or ")}.md')
    handle.write_text(data_source["description"], 'utf8')

for technique in _load('src/config/mitre_attack_11.2.yaml')['techniques']:
    path_prefix = f'src/config/mitre/attack_11.2/techniques/{technique["id"]}'
    _handle = Path(path_prefix)
    _handle.mkdir(parents=True, exist_ok=True)
    handle = Path(f'{path_prefix}/{technique["name"].replace("/", " or ")}.md')
    handle.write_text(technique["description"], 'utf8')
    for sub_technique in technique.get('sub_techniques', []) or []:
        path_prefix = f'src/config/mitre/attack_11.2/sub_techniques/{technique["id"]}/{sub_technique["id"]}'
        _handle = Path(path_prefix)
        _handle.mkdir(parents=True, exist_ok=True)
        handle = Path(f'{path_prefix}/{sub_technique["name"].replace("/", " or ")}.md')
        handle.write_text(sub_technique["description"], 'utf8')
