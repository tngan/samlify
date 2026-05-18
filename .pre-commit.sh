echo "Linting"
npm run lint
LINTRESULT=$?

echo "Compiling"
$(npm bin)/tsc
BUILDRESULT=$?

echo "Type guards"
$(npm bin)/tsc -p tsconfig.typecheck.json
TYPEGUARDRESULT=$?

if [[ $LINTRESULT -ne 0 || $BUILDRESULT -ne 0 || $TYPEGUARDRESULT -ne 0 ]]; then
  echo "Fix errors before commit"
  exit 1
else
  echo "Ok to commit"
  exit 0
fi
