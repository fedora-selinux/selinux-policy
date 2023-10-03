#!/bin/bash
### make-changelog.sh - script for creating rpm changelog entries off commit messages

#set -x

if [ "$1" = "-f" ]
then
  DIST="fedora"
  shift
fi

if ! git remote -v >/dev/null 2>&1
then
  echo This directory does not look like a git repository, exiting.
  exit 1
fi

ORIGIN=`git config --get remote.origin.url`
BRANCH=`git branch --show-current`

# Print ref names without () wrapping
PRETTYFORMAT="%D"
# Look for the latest tag or another decoration in last $HISTORY commits only
HISTORY=${HISTORY-32}
# Skip the first line
STARTFROM="HEAD^"
# Find the latest tag
TAG="`git log --pretty="${PRETTYFORMAT}" -${HISTORY} ${STARTFROM} | grep -m 1 '^tag: '`"
if [ "$?" != 0 ]
then
  # no "tag: "
  TAG="`git log --pretty="${PRETTYFORMAT}" -${HISTORY} ${STARTFROM} | grep -m 1 -v '^$'`" 
fi
TAG="`echo ${TAG} | sed 's/^.*tag: //;s/,.*$//'`"

if [ "$TAG" = "" ]
then
  echo No tag or other decoration found in the latest ${HISTORY} commits, exiting.
  exit 2
fi

# Gather list of all commits up to $TAG
COMMITSLIST=`git log ${TAG}..HEAD --oneline --pretty="%H"`

# for each commit in the list, print the commit subject and the Resolves/Related line
# if not for Fedora, print also the Resolves/Related/Fix line
for COMMIT in ${COMMITSLIST}
do
  git log -1 --pretty="- %s" ${COMMIT}
  [ "$DIST" = "fedora" ] \
  || git show ${COMMIT} | sed 's/^ *//' \
  | grep -e "^Resolves:" -e "^Related:" -e "^Fix:" \
  | sed 's|https://issues.redhat.com/browse/||'
done

