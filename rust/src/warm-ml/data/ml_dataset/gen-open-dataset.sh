#!/bin/bash

echo "[+] Creating open dataset ..."

cd open/http-params-dataset && \
    curl -fL --retry 3 --retry-delay 2 -o input.csv https://github.com/Morzeux/HttpParamsDataset/raw/refs/heads/master/payload_full.csv && \
    python pre_process.py && \
    rm input.csv
cd ../..

cd open/openappsec && \
    curl -fL --retry 3 --retry-delay 2 -o legitimate.zip https://downloads.openappsec.io/waf-comparison-project/legitimate.zip && \
    curl -fL --retry 3 --retry-delay 2 -o malicious.zip https://downloads.openappsec.io/waf-comparison-project/malicious.zip && \
    unzip legitimate.zip $(unzip -Z1 legitimate.zip | head -n 150) && \
    unzip malicious.zip && \
    python pre_process.py && \
    rm -rf Legitimate Malicious legitimate.zip malicious.zip
cd ../..
    
cd open/payload-all-the-things && \
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git && \
    python pre_process.py && \
    rm -rf PayloadsAllTheThings
cd ../..

cd open/polyglot && \
    git clone https://huggingface.co/datasets/darkknight25/polyglot_paylods_datasets && \
    mv polyglot_paylods_datasets/polygot_payloads.jsonl ./malicious_train.jsonl && \
    rm -rf polyglot_paylods_datasets
cd ../..

echo "[+] Done!"

