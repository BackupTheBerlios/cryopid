SITEBASE = ../cryopid/htdocs

PAGES = style.css \
		index.html

# changing these rebuilds everything html
PREREQS = Prettify top.html bottom.html

all: htmlfiles rawfiles
	find $(SITEBASE) -type d -exec chmod 2775 {} \;
	find $(SITEBASE) -type f -exec chmod 664 {} \;


htmlfiles: $(patsubst %,$(SITEBASE)/%,$(filter %.html,$(PAGES)))
rawfiles: $(patsubst %,$(SITEBASE)/%,$(filter-out %.html,$(PAGES)))

# HTML files need a bit of processing.
$(SITEBASE)/%.html: %.html $(PREREQS)
	./Prettify $< > $@

# everything else can go through unharmed
$(SITEBASE)/%: %
	cp $< $@

clean:
	rm -f $(HOWTO_BASENAME)*.html $(FAQ_BASENAME)*.html
	# Not touching the site base directory!

backup: clean
	cd .. && tar czf sitefiles-`date +"%Y%m%d"`.tar.gz sitefiles/

push: 
	cd .. && rsync -azve ssh cpsite dagobah@shell.berlios.de: && ssh dagobah@shell.berlios.de make -C cpsite

.PHONY: htmlfiles rawfiles howto clean backup push demo
