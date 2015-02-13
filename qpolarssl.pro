TEMPLATE = subdirs

SUBDIRS += library
SUBDIRS += tests

tests.depends = library
