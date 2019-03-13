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
	# for java runtime support library
	# need to run with npm install, yarn add --ignore-scripts will ignore the postinstall script
	# check more information in the package.json of @authenio/xsd-schema-validator
	npm install @authenio/xsd-schema-validator;

else ifeq ($(SAML_VALIDATOR), libxml)
	@echo "Installing libxml-xsd ...";
	npm install libxml-xsd

else ifeq ($(SAML_VALIDATOR), xmllint)
	@echo "Installing node-xmllint ...";
	npm i node-xmllint

else
	@echo "No valid SAML_VALIDATOR is chosen";
endif

doc: ;@echo "prepare and serve the docs"; \
	   docsify serve ./docs

.PHONY: rebuild pretest doc validator
