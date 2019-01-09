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

validator: ;
ifeq ($(SAML_VALIDATOR), javac)
	@echo "Installing java xsd schema validator ...";
	yarn add --ignore-scripts @passify/xsd-schema-validator;
else ifeq ($(SAML_VALIDATOR), libxmljs)
	@echo "Installing libxmljs-mt ...";
	yarn add --ignore-scripts libxmljs-mt;
else
	@echo "No valid SAML_VALIDATOR is chosen";
endif

doc: ;@echo "prepare and serve the docs"; \
	   docsify serve ./docs

.PHONY: rebuild pretest doc validator
