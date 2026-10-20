echo "Linting"
yarn -s lint
LINTRESULT=$?

echo "Compiling"
npx tsc --noEmit
BUILDRESULT=$?

echo "Type guards"
npx tsc -p tsconfig.typecheck.json
TYPEGUARDRESULT=$?

if [[ $LINTRESULT -ne 0 || $BUILDRESULT -ne 0 || $TYPEGUARDRESULT -ne 0 ]]; then
  echo "Fix errors before commit"
  exit 1
else
  echo "Ok to commit"
  exit 0
fi
