#!/usr/bin/env bash

source_folder="uncategorized"
# target_folder="neutral"
target_folder="unseen/neutral"

mkdir -p "./data/${target_folder}/"

while IFS= read -r file; do
  mv "./data/${source_folder}/html/${file}.html" "./data/${target_folder}/" || true
  rm data/${source_folder}/jpeg/${file}.jpg || true
  aws s3 rm "s3://ario-infra-ml-training-data/${source_folder}/jpeg/${file}.jpg"
  aws s3 mv "s3://ario-infra-ml-training-data/${source_folder}/html/${file}.html" "s3://ario-infra-ml-training-data/${target_folder}/"
done < file_list.txt
