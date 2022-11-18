from typing import Union
from glob import glob
from pathlib import Path

from markdown import markdown
import yaml


def str_presenter(dumper, data):
    if len(data) > 50:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

yaml.add_representer(str, str_presenter)
yaml.representer.SafeRepresenter.add_representer(str, str_presenter)


PROJ_ROOT = str(Path(__file__).parent.parent)

rule_descriptions = {}
for file_name in glob(f"{PROJ_ROOT}/src/config/rules/*.md"):
    description = markdown(Path(file_name).read_text(encoding='utf8'), output_format="html")
    name = file_name.split('/')[-1]
    if name.startswith('recommendation_'):
        rule_num = file_name.split('/')[-1].replace('recommendation_', '').strip('.md')
        rule_descriptions.setdefault(rule_num, {})
        rule_descriptions[rule_num]['recommendation'] = description
    if name.startswith('issue_'):
        rule_num = file_name.split('/')[-1].replace('issue_', '').strip('.md')
        rule_descriptions.setdefault(rule_num, {})
        rule_descriptions[rule_num]['issue'] = description

with open(f'{PROJ_ROOT}/src/config/rule_desc.yaml', 'w', encoding='utf8') as handle:
    yaml.safe_dump_all([rule_descriptions], stream=handle, indent=4, encoding='utf8', default_flow_style=False)

pci_dss = {
    'version': "3.2.1",
    'requirements': {}
}
for file_name in glob(f"{PROJ_ROOT}/src/config/pci_dss/3.2.1/*.md"):
    description = markdown(Path(file_name).read_text(encoding='utf8'), output_format="html")
    requirement = file_name.split('/')[-1].replace('requirement_', '').strip('.md')
    pci_dss['requirements'][requirement] = description

with open(f'{PROJ_ROOT}/src/config/pci_dss_3.2.1.yaml', 'w', encoding='utf8') as handle:
    yaml.safe_dump_all([pci_dss], stream=handle, indent=4, encoding='utf8', default_flow_style=False)

pci_dss = {
    'version': "4.0",
    'requirements': {}
}
for file_name in glob(f"{PROJ_ROOT}/src/config/pci_dss/4.0/*.md"):
    description = markdown(Path(file_name).read_text(encoding='utf8'), output_format="html")
    requirement = file_name.split('/')[-1].replace('requirement_', '').strip('.md')
    pci_dss['requirements'][requirement] = description

with open(f'{PROJ_ROOT}/src/config/pci_dss_4.0.yaml', 'w', encoding='utf8') as handle:
    yaml.safe_dump_all([pci_dss], stream=handle, indent=4, encoding='utf8', default_flow_style=False)

mitre_attack = {
    'version': "11.2",
    'tactics_base_url': "https://attack.mitre.org/tactics/",
    'tactics': [],
    'mitigations_base_url': "https://attack.mitre.org/mitigations/",
    'mitigations': [],
    'data_sources_base_url': "https://attack.mitre.org/datasources/",
    'data_sources': [],
    'techniques_base_url': "https://attack.mitre.org/techniques/",
    'techniques': [],
}
for file_name in glob(f"{PROJ_ROOT}/src/config/mitre/attack_11.2/tactics/*/*.md"):
    item = {
        'id': file_name.split('/')[-2],
        'name': file_name.split('/')[-1].strip('.md'),
        'description': markdown(Path(file_name).read_text(encoding='utf8'), output_format="html")
    }
    mitre_attack['tactics'].append(item)

for file_name in glob(f"{PROJ_ROOT}/src/config/mitre/attack_11.2/mitigations/*/*.md"):
    item = {
        'id': file_name.split('/')[-2],
        'name': file_name.split('/')[-1].strip('.md'),
        'description': markdown(Path(file_name).read_text(encoding='utf8'), output_format="html")
    }
    mitre_attack['mitigations'].append(item)

for file_name in glob(f"{PROJ_ROOT}/src/config/mitre/attack_11.2/data_sources/*/*.md"):
    item = {
        'id': file_name.split('/')[-2],
        'name': file_name.split('/')[-1].strip('.md'),
        'description': markdown(Path(file_name).read_text(encoding='utf8'), output_format="html")
    }
    mitre_attack['data_sources'].append(item)

for file_name in glob(f"{PROJ_ROOT}/src/config/mitre/attack_11.2/techniques/*/*.md"):
    techniques_id = file_name.split('/')[-2]
    techniques: dict[str, Union[str,list]] = {
        'id': techniques_id,
        'name': file_name.split('/')[-1].strip('.md'),
        'description': markdown(Path(file_name).read_text(encoding='utf8'), output_format="html"),
    }
    sub_techniques = []
    for _file_name in glob(f"{PROJ_ROOT}/src/config/mitre/attack_11.2/sub_techniques/{techniques_id}/*/*.md"):
        sub_item = {
            'id': _file_name.split('/')[-2],
            'name': _file_name.split('/')[-1].strip('.md'),
            'description': markdown(Path(_file_name).read_text(encoding='utf8'), output_format="html")
        }
        sub_techniques.append(sub_item)
    if sub_techniques:
        techniques['sub_techniques'] = sub_techniques
    mitre_attack['techniques'].append(techniques)

with open(f'{PROJ_ROOT}/src/config/mitre_attack_11.2.yaml', 'w', encoding='utf8') as handle:
    yaml.safe_dump_all([mitre_attack], stream=handle, indent=4, encoding='utf8', default_flow_style=False)
