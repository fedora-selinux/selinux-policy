## Merging selinux-policy-contrib repository with selinux-policy

On November 25th, 2020, the selinux-policy-contrib repository was merged with selinux-policy.

Previously, SELinux policy packages in Fedora used 2 repositories:
base [1] and contrib [2].
This division into two repos was merely a historical artifact, being
now just a source of confusion and made dealing
with SELinux policy repos more difficult.

From now on, these repos are merged into one, containing sources from both.
All the changes affect both repos, `rawhide` branches and future branches
`f34` and newer.
When working in the rawhide branch, only the base repo is
now used; the corresponding contrib branch was archived and will not be used
any longer. The contrib repo's commit history are a part of the base repo.
Stable branches (`f33`, `f32`, all older ones) remain unchanged.

It mainly is an internal change of where the git repository is stored and
how it is referenced. There should now be just one notable change
inside the repo: all files previously accessible from the root directory in the
selinux-policy-contrib repo are in the selinux-policy base repo, directory
`policy/modules/contrib/`. No change for working in the selinux-policy base repo.

### How users are affected?
There is no change for users.

### How custom selinux-policy developers are affected?
No change for policy writing other than where to look for modules, previously found in the contrib repo.

Scripts, data, specfile, etc. in the dist git were updated to use the new location for builds targeting rawhide or f34+.

### How selinux-policy contributors are affected?
No change other than where to look for the previous contrib modules and where to submit pull requests.

Pull requests which have not been merged yet require the submitter to rebase it and open against the base repo.

### Where to submit pull requests?
Use the base selinux-policy repository [3].

### How to report issues?
Use the base selinux-policy repository [4].

### Backporting commits
Commits to policy/modules/contrib needing backport to stable branches will be backported to the legacy contrib repo.

### References
[1] https://github.com/fedora-selinux/selinux-policy/

[2] https://github.com/fedora-selinux/selinux-policy-contrib/

[3] https://github.com/fedora-selinux/selinux-policy/pulls

[4] https://github.com/fedora-selinux/selinux-policy/issues
