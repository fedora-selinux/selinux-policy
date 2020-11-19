## Merging selinux-policy-contrib repository with selinux-policy

Currently, SELinux policy packages in Fedora use 2 repositories:
base [1] and contrib [2].
This division into two repos is merely a historical artifact.
It currently is just a source of confusion and makes dealing
with SELinux policy repos more difficult.

We work on a change to merge these repos into one, containing sources from both.
All the changes would affect both repos, `rawhide` branches and future branches
`f34` and newer.
After the merge, when working in the rawhide branch, only the base repo would
be used; the corresponding contrib branch would be archived and not used
any longer. The contrib repo's commit history would be a part of the base repo.
Stable branches (`f33`, `f32`, all older ones) would remain unchanged.
The plan is to make it happen in the week starting with Monday, November 23rd.

It mainly is an internal change of where the git repository is stored and
how it is referenced. After the merge, there will be just one notable change
inside the repo: all files previously accessible from the root directory in the
selinux-policy-contrib repo will be in the selinux-policy base repo, directory
`policy/modules/contrib/`. No change for working in the selinux-policy base repo.

### How users will be affected?
There is no change for users.

How custom selinux-policy developers will be affected?
No change for policy writing other than where to look for modules, previously found in the contrib repo.

Scripts, data, specfile, etc. in the dist git will be updated to use the new location for builds targeting rawhide or f34+.

### How selinux-policy contributors will be affected?
No change other then where to look for the previous contrib modules and where to submit pull requests.

Pull requests which have not been merged yet would require the submitter to rebase it and open against the base repo.

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
