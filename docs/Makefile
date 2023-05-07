.PHONY: help
help:
	@echo "Usage : make <commands>"
	@echo "available commands : clean | build | serve | serve-zh_CN | build-zh_CN"
	@echo "---"
	@echo "Hint :"
	@echo "English: make clean; make build; make serve"
	@echo "中文: make clean; make build-zh_CN; make serve-zh_CN"
	@echo "---"
	@grep -hE '##' Makefile  | grep -v grep | sed -e 's/\\$$//' | sed -e 's/##/,/'  | sed -e 's/:.*,/ ,/' | column -t -c2 -s,


hub:
	git clone --depth=1 https://github.com/bytedance/Elkeid-HUB.git
	cp -r Elkeid-HUB/docs hub
	cp Elkeid-HUB/*.png hub/
	cp Elkeid-HUB/*.md hub/

copy: hub
	python grab.py
	cp -r enterprise_edition sources/
	cp -r ElkeidData sources/
	cp -r hub sources/
	cp filter.py sources/

serve-zh_CN: copy
	cp SUMMARY-zh_CN.md sources/SUMMARY.md
	cp book-zh_CN.toml sources/book.toml
	cd sources && mdbook serve

build-zh_CN: copy
	cp SUMMARY-zh_CN.md sources/SUMMARY.md
	cp book-zh_CN.toml sources/book.toml
	cd sources && mdbook build

serve: copy
	cp SUMMARY.md sources/SUMMARY.md
	cp book.toml sources/
	cd sources && mdbook serve

build: copy
	cp SUMMARY.md sources/SUMMARY.md
	cp book.toml sources/
	cd sources && mdbook build

clean:
	rm -rf sources
