#!/usr/bin/env bash
mkdir -p data
aws s3 sync s3://ario-infra-ml-training-data ./data
