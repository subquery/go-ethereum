## Subquery changes

// TODO

## Applying changes to forks

Many other networks and L2s use forks of geth we can apply the changes to these forks using the following steps

1. Generate a patch between the feature branch and master
`git format-patch --stdout <sha1>..<sha2> > subql.patch`

2. In the for repo ensure that the subquery geth for is a remote

You can check this with `git remote -v` and `git@github.com:subquery/go-ethereum.git` should be one of the remotes
If it is not a remote it can be added with `git remote add geth git@github.com:subquery/go-ethereum.git && git fetch geth`

This ensures that when appling the patch that commits are available

3. Apply the patch to the forked repo

`git am -3 /path/to/subql.patch`

This will apply the changes but may require resolving some conflicts

4. Fixing build issues

These forks are generally behind the master geth branch. This can mean that further changes are requied to get builds suceeding.

It's suggested to create a patch or patches of these changes to make it easier to sync changes from the fork and from geth in the future

You can do this by repeating steps 1, 3

e.g `git format-patch --stdout 2d772be398d851a62be53d1b0c162c45bb4876e3..c9760f18c15b8d36af7ef1a9bf5b21056f633b71 > build_fixes.patch`
