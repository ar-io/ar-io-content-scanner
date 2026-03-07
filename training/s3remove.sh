#!/usr/bin/env bash

txid="W0wWCgoxUKL2wtklbWRfIlkDwlp0vOb2QT26XqNgCBQ"


aws s3 rm "s3://ario-infra-ml-training-data/uncategorized/html/${txid}.html"
aws s3 rm "s3://ario-infra-ml-training-data/uncategorized/jpeg/${txid}.jpg"
rm data/uncategorized/html/${txid}.html || true
rm data/uncategorized/jpeg/${txid}.jpg || true
