#!/bin/sh

czertainlyHome="/opt/czertainly"
source ${czertainlyHome}/static-functions

log "INFO" "Launching the Software Cryptography Provider"
java $JAVA_OPTS -jar ./app.jar

#exec "$@"