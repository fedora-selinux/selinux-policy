 to create a selinux-policy build for RHEL

These instructions contain command examples which are not expected to be copied
literally without understanding the effect. Refer to the RHEL development guide
for more information:
https://one.redhat.com/rhel-development-guide/#assembly_rhel-9-development_rhel-dev-guide

Most of the information is common for RHEL 9 (centos c9s stream, z-stream)
and RHEL 8 (centos c8s stream, z-stream).

## Gather commits list

Switch to the gitlab.cee git repo with selinux-policy sources, synchronize it,
verify the status, collect the list of updates, format the log for the changelog
rpm section and for commit message further processing using git-trailers or the
make-changelog.sh script.

```
git fetch --all
git remote -v
git pull upstream rhel-9.1.0
git push origin rhel-9.1.0
git status
git log

git log $(git describe --tags --abbrev=0)..HEAD --format="- %s %n%(trailers:key=Resolves)%(trailers:key=Related)%(trailers:key=Fix)" \
| sed '/^\s*$/d; s/ $//' \
| sed 's|https://issues.redhat.com/browse/||' \
| tee /tmp/COMMITS
```

tag the latest commit and push the tag
```
git tag v34.1.28
git push upstream-rw v34.1.28
```

## Make a PR to prepare the build
Switch to the gitlab.com dist-git repo with package sources, synchronize it, check the status.
Use either a temporary branch name, or c8s/c9s branch directly, but note these branches are marked protected by default so force-pushing (in case of reiterating the build) is not allowed unless unprotected.

Before starting to work in gitlab.com, ensure you have a valid kerberos ticket
and you were logged in: https://red.ht/GitLabSSO

```
git fetch --all
git remote -v
git status
git pull origin branchname
git log
```

remove stale files, download the latest sources, update specfile and the sources file, verify that hashes have changed in specfile and sources
```
ls -trog selinux-policy*tar.gz | tail
rm selinux-policy-HASH.tar.gz
rm selinux-policy*.rpm
./make-rhat-patches.sh
git diff
```

edit specfile, update changelog, verify diff += changelog entries, check and store changelog
```
  c9s>>> rpmdev-bumpspec -n 34.1.28 selinux-policy.spec
  c8s>>> rpmdev-bumpspec selinux-policy.spec
z-str>>> rpmdev-bumpspec -r selinux-policy.spec
rhel9>>> gvim +813 selinux-policy.spec
rhel8>>> gvim +722 selinux-policy.spec
>>> in vi, use :r /tmp/COMMITS
git diff
sed -n '1,/^%changelog/d;1,/^$/p' selinux-policy.spec |tee /tmp/CHANGELOG
```

upload sources to dist-git lookaside cache (always 3 files), add changed files to git index (only 2 changes hunks: sources, specfile), commit changes to the repo with changelog content as the commit message
```
ls -trog selinux-policy*tar.gz | tail -n1
  c9s>>> centpkg new-sources selinux-policy-HASH.tar.gz container-selinux.tgz macro-expander
  c8s>>> centpkg new-sources selinux-policy-HASH.tar.gz selinux-policy-contrib-HASH.tar.gz container-selinux.tgz macro-expander
z9str>>> rhpkg new-sources selinux-policy-HASH.tar.gz container-selinux.tgz macro-expander
z8str>>> rhpkg new-sources selinux-policy-HASH.tar.gz selinux-policy-contrib-HASH.tar.gz container-selinux.tgz macro-expander
git add -p
git commit
>>> in vi, use :0r /tmp/CHANGELOG
```

push changes to the remote git repo and initiate a scratchbuild
```
git log
git remote -v
git push fork branchname
 c89s>>> centpkg build --scratch --srpm
z-str>>> rhpkg build --scratch --srpm
```

open a pull request in dist-git, log in first: https://red.ht/GitLabSSO
- centos: https://gitlab.com/LOGIN/selinux-policy/-/merge_requests/new?merge_request%5Bsource_branch%5D=c9s
- c8s: https://gitlab.com/LOGIN/selinux-policy/-/merge_requests/new?merge_request%5Bsource_project_id%5D=26064476&merge_request%5Bsource_branch%5D=c8s&merge_request%5Btarget_project_id%5D=23693270&merge_request%5Btarget_branch%5D=c8s
- 8.8.z: https://gitlab.com/LOGIN/rhel-rpms-selinux-policy/-/merge_requests/new?merge_request%5Bsource_project_id%5D=40153481&merge_request%5Bsource_branch%5D=rhel-8.8.0&merge_request%5Btarget_project_id%5D=40115504&merge_request%5Btarget_branch%5D=rhel-8.8.0

Do not forget to untick:
```
Delete source branch when merge request is accepted.
```
if using the main branches (c9s, c8s, rhel-X.Y.0).

Wait about 3 minutes for
```
CentOS Stream Zuul CI @centos-stream-zuul-ci-bot approved this merge request 1 minutes ago
```

Although non-voting, tests are still executed and last 2+ hours.

Start the merge train, wait about 3 minutes:
```
Added to the merge train
...
Merged by / The changes were merged into c9s / The source branch has been deleted
> ctrl-r => Merge requests: 0 in the left column
```

## Create the build
Wait about 5 minutes for the changes to propagate to all infrastructure
systems, synchronize the repos, and create a build.

Use `centpkg --release c8s/c9s build --switches` in case the current branch is different (ensure you keep the arguments order).

Note the build commands are sensitive to which kerberos tickets are valid;
using kswitch is not reliable; older tickets are often ignored when network
reconnections or VPN resets occured in the meantime.
The safest known way is to destroy all kerberos principals and get a new one
for IPA.REDHAT.COM only right before the build starts.
```
kswitch login@IPA.REDHAT.COM
-or-
kdestroy -a
kinit login@IPA.REDHAT.COM
```

### c8s/c9s
```
git co c8s
git fetch origin; git fetch rhel
   > 1b1eb8edb..29d572116  c8s        -> origin/c8s
   > 1b1eb8edb..29d572116  rhel-8-main -> rhel/rhel-8-main
git pull origin c8s
git push fork c8s
git log
    > commit 29d572116 (HEAD -> c8s, rhel/rhel-8-main, origin/c8s, fork/c8s)
git status
centpkg build
```

### z-stream
```
git fetch gitlab-origin; git fetch origin
From gitlab.com:redhat/rhel/rpms/selinux-policy
   214cea7a3..071e1be2d  rhel-8.8.0 -> gitlab-origin/rhel-8.8.0
From ssh://pkgs.devel.redhat.com/rpms/selinux-policy
   214cea7a3..071e1be2d  rhel-8.8.0 -> origin/rhel-8.8.0
git log
commit 071e1be2d3 (HEAD -> rhel-8.8.0, origin/rhel-8.8.0, gitlab-origin/rhel-8.8.0, gitlab-fork/rhel-8.8.0)
git status
rhpkg build
...
```

## When build finishes
Once the build finishes successfully,
filter jiras list by "Fixed in Build: selinux-policy-3.14.3-129.el8",
change the state to Integration,
raise the "Preliminary Testing: Requested" flag,
set the Docs Impact fiels.
In bugzilla, switch bzs to the Modified state (check you are logged in),
set the Doc Type and Doc Text fields.
- https://url.corp.redhat.com/rhel9-selinuxpolicy-post
- https://url.corp.redhat.com/rhel8-selinuxpolicy-post
- https://url.corp.redhat.com/40d017f
- https://url.corp.redhat.com/6ae54ab

Build will appear here:
- centos: https://kojihub.stream.rdu2.redhat.com/koji/packageinfo?packageID=2076
- rhel: https://brewweb.engineering.redhat.com/brew/packageinfo?packageID=2989

The rhel repository link looks like:
- https://brew-task-repos.engineering.redhat.com/repos/official/selinux-policy/3.14.3/117.el8_8.2/

The following file can be directly used as a repo file:
- https://brew-task-repos.engineering.redhat.com/repos/official/selinux-policy/3.14.3/95.el8_6.11/selinux-policy-3.14.3-95.el8_6.11.repo

Then, gating is initiated. As soon as the build passes gating, it can be added
to erratum (automatically or manually) as well as bugs references.
- https://errata.devel.redhat.com/advisory/filters/new?search=selinux-policy

----
## Initial settings
Setup for git and dist-git is needed, the latter different for main development
branches (c8s/c9s) and z-stream

- a selinux-policy gitlab.cee git repository with policy sources
  - git remotes:
```
origin  git@gitlab.cee.redhat.com:login/selinux-policy.git (fetch)
upstream        https://gitlab.cee.redhat.com/SELinux/selinux-policy.git (fetch)
upstream-rw     git@gitlab.cee.redhat.com:SELinux/selinux-policy.git (fetch)
fedora     https://github.com/fedora-selinux/selinux-policy.git (fetch)
```

- a selinux-policy gitlab.com dist-git repository with package sources for main development branches (c8s/c9s)
  - git remotes:
```
fedora  ssh://login@pkgs.fedoraproject.org/rpms/selinux-policy (fetch)
fork    git@gitlab.com:login/selinux-policy.git (fetch)
origin  https://gitlab.com/redhat/centos-stream/rpms/selinux-policy (fetch)
rhel    ssh://login@pkgs.devel.redhat.com/rpms/selinux-policy (fetch)
```

- a selinux-policy gitlab.com dist-git repository with package sources for z-stream branches
(especially note there are different repos, not just branches)
  - git remotes:
```
gitlab-centos   git@gitlab.com:redhat/centos-stream/rpms/selinux-policy.git (fetch)
gitlab-fork     git@gitlab.com:login/rhel-rpms-selinux-policy.git (fetch)
gitlab-origin   git@gitlab.com:redhat/rhel/rpms/selinux-policy.git (fetch)
origin  ssh://login@pkgs.devel.redhat.com/rpms/selinux-policy (fetch)
```

