#!/usr/bin/env python3
# Copyright 2026 Jeremiah Jordan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Generate versioned normalized wire names from the pinned OASIS sources."""
import json,pathlib,re
from bs4 import BeautifulSoup
from check_license import HEADER

def normalize(s):
    s=s.replace('(',' ').replace(')',' ')
    s=re.sub(r'[^A-Za-z0-9_](?=[A-Za-z][a-z])',' ',s)
    s=re.sub(r'[^A-Za-z0-9_\s]','_',s)
    words=s.split()
    if not words:return ''
    words[0]=re.sub(r'^(\d+)(.+)$',r'\2\1',words[0])
    return ''.join(w[0].upper()+w[1:] for w in words)

result={}
for version in ['1.0','1.1','1.2','1.3','1.4','2.0','2.1','3.0']:
    soup=BeautifulSoup(pathlib.Path(f'.cache/specs/{version}.html').read_bytes(),'html.parser');tags={};enums={}
    for table in soup.find_all('table'):
        rows=table.find_all('tr')
        if not rows:continue
        # HTML span boundaries can split a word (e.g. 2.1's "Operatio" + "n").
        # Preserve source whitespace rather than inserting separators at every span.
        title=normalize(rows[0].get_text('',strip=False))
        if title.endswith('Name'):title=title[:-4]
        # These source tables mistakenly label their headers "State Name".
        # Their section titles and dedicated tags identify the enumerations.
        heading=table.find_previous(['h1','h2','h3','h4'])
        if heading and title=='State':
            section=heading.get_text(' ',strip=True)
            if section.endswith('Split Key Polynomial Enumeration'):
                assert version=='3.0' and 'Polynomial-283' in table.get_text(' ',strip=True)
                title='SplitKeyPolynomial'
            elif section.endswith('Ticket Type Enumeration'):
                assert version in ['2.0','2.1','3.0'] and 'Login' in table.get_text(' ',strip=True)
                title='TicketType'
        # The 2.0, 2.1 and 3.0 Endpoint Role table (2.0/2.1 11.19, 3.0 11.20)
        # is headed "Encoding Option Name" although its caption and section
        # title say Endpoint Role. Without this its Client/Server rows would
        # be merged into Encoding Option and Endpoint Role would have no names.
        if heading and title=='EncodingOption' and heading.get_text(' ',strip=True).endswith('Endpoint Role Enumeration'):
            assert version in ['2.0','2.1','3.0'] and 'Client' in table.get_text(' ',strip=True)
            title='EndpointRole'
        text=table.get_text(' ',strip=True);is_tags='420001' in text and 'Activation Date' in text
        for row in rows:
            cells=[re.sub(r'\s+',' ',c.get_text('',strip=False)).strip() for c in row.find_all('td')]
            if len(cells)<2 or cells[0].startswith(('Reserved','Extensions')):continue
            if is_tags and re.fullmatch(r'(?:0[xX])?[0-9a-fA-F]{6}',cells[1]):tags[normalize(cells[0])]=int(cells[1],16)
            elif title and (match:=re.fullmatch(r'((?:0[xX])?[0-9a-fA-F]{8})(?:\s+\(deprecated\))?',cells[1],re.IGNORECASE)):
                enums.setdefault(title,{})[normalize(cells[0])]=int(match[1],16)
    # Mathematical superscripts are not word boundaries. The official XML
    # traces normalize GF(2^16) and GF(2^8) with an underscore before exponent.
    for source,target,code in [('PolynomialSharingGF216','PolynomialSharingGF2_16',2),('PolynomialSharingGF28','PolynomialSharingGF2_8',4)]:
        methods=enums.get('SplitKeyMethod',{})
        if source in methods:
            assert methods[source]==code
            methods[target]=code
            # The unchanged OVH SDK emits the concatenated exponent spelling
            # in JSON/XML. Keep it as an explicit, edition-scoped alias for
            # the official trace spelling; do not guess other enum spellings.
    aliases={'BatchErrorContinuationOption':'BatchErrorContinuation','MaskGeneratorHashingAlgorithm':'HashingAlgorithm','UniqueIdentifier':'UniqueIdentifierEnumerations','PrivateKeyUniqueIdentifier':'UniqueIdentifierEnumerations','PublicKeyUniqueIdentifier':'UniqueIdentifierEnumerations','LinkedObjectIdentifier':'UniqueIdentifierEnumerations'}
    for field,table in aliases.items():
        if field in tags and table in enums:enums[field]=dict(enums[table])
    # Later editions print MFG1 in the table; the mechanism prose and official
    # profile traces retain MGF1. Accept both spellings of the same code.
    if 'MaskGenerator' in enums and 'MFG1' in enums['MaskGenerator']:
        enums['MaskGenerator']['MGF1']=enums['MaskGenerator']['MFG1']
    assert tags['RequestMessage']==0x420078 and enums['CryptographicAlgorithm']['AES']==3
    assert enums['Operation']['Create']==1 and enums['Operation']['Get']==10
    result[version]={'tags':tags,'enums':enums}
path=pathlib.Path('src/wire_registry.json');path.write_text(json.dumps(result,sort_keys=True,separators=(',',':'))+'\n');path.with_name(path.name+'.license').write_text(HEADER)
print('Generated',path,'for',len(result),'versions')
