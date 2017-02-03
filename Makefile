PROJECT = "express-saml2"

install: ;@echo "install ${PROJECT}"; \
				 yarn;

clean:	;
				rm -rf node_modules

rebuild: ;
	       rm -rf build; tsc; \

.PHONY: rebuild
