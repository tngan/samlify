PROJECT = "samlify"

install: ;@echo "install ${PROJECT}"; \
				 npm install;

clean:	;
				rm -rf node_modules

rebuild: ;
	       rm -rf build; \
				 tsc; \
				 cp -a schemas build;

pretest:	;
					mkdir -p build/test; \
					cp -a schemas build; \
					cp -a test/key test/misc build/test;

doc: ;@echo "prepare and serve the docs"; \
	   docsify serve ./docs

.PHONY: rebuild pretest doc
