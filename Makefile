PROJECT = "express-saml2"

install: ;@echo "install ${PROJECT}"; \
				 yarn;

clean:	;
				rm -rf node_modules

rebuild: ;
	       rm -rf build; tsc;

pretest:	;
					mkdir -p build/test; \
					cp -a test/key test/misc build/test;

.PHONY: rebuild pretest
