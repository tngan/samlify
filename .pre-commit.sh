#!/bin/sh
# Installed by `yarn hooks:postinstall`.
yarn -s lint && yarn -s test:types || {
  echo "Fix errors before commit"
  exit 1
}
