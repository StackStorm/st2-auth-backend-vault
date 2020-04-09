ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
VIRTUALENV_DIR ?= $(ROOT_DIR)/virtualenv

.PHONY: all
all: requirements virtualenv tox

.PHONY: clean
clean: .clean-virtualenv

# list all makefile targets
.PHONY: .list
.list:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs

.PHONY: requirements
requirements: virtualenv
	@echo
	@echo "==================== requirements ===================="
	@echo
	@echo "Start Time = `date --iso-8601=ns`"
	. $(VIRTUALENV_DIR)/bin/activate; \
	$(VIRTUALENV_DIR)/bin/pip install --cache-dir $(HOME)/.pip-cache --upgrade pip; \
	$(VIRTUALENV_DIR)/bin/pip install --cache-dir $(HOME)/.pip-cache -q -r $(ROOT_DIR)/requirements.txt; \
	$(VIRTUALENV_DIR)/bin/pip install --cache-dir $(HOME)/.pip-cache -q -r $(ROOT_DIR)/test-requirements.txt;
	@echo "End Time = `date --iso-8601=ns`"

.PHONY: virtualenv
virtualenv: $(VIRTUALENV_DIR)/bin/activate
$(VIRTUALENV_DIR)/bin/activate:
	@echo
	@echo "==================== virtualenv ===================="
	@echo
	@echo "Start Time = `date --iso-8601=ns`"
	if [ ! -d "$(VIRTUALENV_DIR)" ]; then \
		if [ -d "$(ROOT_VIRTUALENV)" ]; then \
			$(ROOT_DIR)/bin/clonevirtualenv.py $(ROOT_VIRTUALENV) $(VIRTUALENV_DIR);\
		else \
			virtualenv --no-site-packages $(VIRTUALENV_DIR);\
		fi; \
	fi;
	@echo "End Time = `date --iso-8601=ns`"

.PHONY: .clean-virtualenv
.clean-virtualenv:
	@echo
	@echo "==================== cleaning virtualenv ===================="
	@echo
	@echo "Start Time = `date --iso-8601=ns`"
	rm -rf $(VIRTUALENV_DIR)
	@echo "End Time = `date --iso-8601=ns`"

.PHONY: tox
tox: requirements
	@echo
	@echo "==================== tox ===================="
	@echo
	@echo "Start Time = `date --iso-8601=ns`"
	. $(VIRTUALENV_DIR)/bin/activate; \
	$(VIRTUALENV_DIR)/bin/tox
	@echo "End Time = `date --iso-8601=ns`"
