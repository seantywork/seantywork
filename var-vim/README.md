# vim

```shell
# ~/.vimrc
filetype plugin indent on
" show existing tab with 4 spaces width
set tabstop=4
" when indenting with '>', use 4 spaces width
set shiftwidth=4
" On pressing tab, insert 4 spaces
set expandtab

```


```shell

# ctags

sudo apt install universla-ctags


ctags -R --C-kinds=+p $SRC_DIR $TARGET_DIR

# in vim
:set tags+=<taglocation>
:tag /<PATTERN_TO_FIND>
```
