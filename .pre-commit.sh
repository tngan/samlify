#!/bin/sh
# Installed by `yarn hooks:postinstall`.
yarn -s lint && npx tsc --noEmit && npx tsc -p tsconfig.typecheck.json || {
  echo "Fix errors before commit"
  exit 1
}
