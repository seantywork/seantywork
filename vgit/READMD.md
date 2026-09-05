# git

```shell
# clone
git clone 

# commit

git add .
git commit -m "message"

# remote
git remote add
git remote remove

# duplicate

git clone --bare https://github.com/EXAMPLE-USER/OLD-REPOSITORY.git

git push --mirror https://github.com/EXAMPLE-USER/NEW-REPOSITORY.git

# switch 

git switch -c new branch

# merge

git merge other_branch

# fetch

git fetch branch

# rebase

git rebase remote branch

# squash

git reset --soft HEAD~$COMMIT_COUNT

git commit -m "new message"

# squash (interactive)

git rebase -i HEAD~$COMMIT_TO_SQUASH

# diff

git diff commit commit

# log

git log

# patch

git diff > new.patch

git apply new.patch

# reset 

git reset --hard branch


```
