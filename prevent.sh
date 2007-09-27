#!/bin/sh
cov-build --dir ~/cov/mod_whoisd/ --config /opt/prevent-linux64-3.6.1/config/coverity_config.xml make && \
cov-analyze --all --dir ~/cov/mod_whoisd/ --config /opt/prevent-linux64-3.6.1/config/coverity_config.xml && \
cov-commit-defects --datadir ~/cov/gui/ --product mod_whoisd --user ondrej --dir ~/cov/mod_whoisd/
