#!/bin/bash

for file in $(git diff --cached --name-only --diff-filter=d | grep -E '\.(ts|js)$')
do
  git show ":$file" | node_modules/.bin/tslint "$file" # we only want to lint the staged changes, not any un-staged changes
  if [ $? -ne 0 ]; then
    echo "TSLint failed on staged file '$file'. Please check your code and try again. You can run TSLint manually via npm run tslint."
    exit 1 # exit with failure status
  fi
done